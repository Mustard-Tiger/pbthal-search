from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
from flask_session import Session
import os
import requests
from bs4 import BeautifulSoup
import time
from urllib.parse import urljoin, quote_plus, urlparse
import re
from requests.cookies import create_cookie

app = Flask(__name__)

# Get secret key from environment or generate a fixed one
secret_key = os.environ.get('SECRET_KEY')
if not secret_key:
    # Generate a random key and convert to hex string (for development)
    secret_key = os.urandom(24).hex()
    print("WARNING: SECRET_KEY not set in environment. Using generated key (not persistent!)")

app.secret_key = secret_key
CORS(app, supports_credentials=True)  # Enable credentials for cookie passthrough

# Configure Flask-Session for persistent sessions
app.config['SESSION_TYPE'] = 'filesystem'
sess = Session()
sess.init_app(app)

BASE_URL = 'https://tonepoet.fans'
REAL_DEBRID_API_BASE = 'https://api.real-debrid.com/rest/1.0'


def get_authenticated_session():
    """Get or create a requests session with user's forum cookies"""
    # Create a new session and restore cookies from Flask session
    # This allows WordPress to set additional session cookies that persist across requests
    # Note: We can't store requests.Session objects in Flask session (not serializable),
    # so we create a new session each time but restore cookies from Flask session
    user_session = requests.Session()
    user_session.trust_env = False  # ignore HTTP(S)_PROXY and similar env vars
    user_session.proxies = {"http": None, "https": None}
    user_session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36'
    })

    # Restore cookies from Flask session
    stored = session.get('forum_cookies', [])

    # Backward compatibility: support the old dict format from the original code
    if isinstance(stored, dict):
        for name, value in stored.items():
            user_session.cookies.set(name, value, domain='tonepoet.fans')

    # New format: preserve domain/path/secure/expires from Netscape cookie imports
    elif isinstance(stored, list):
        for c in stored:
            try:
                cookie = create_cookie(
                    name=c['name'],
                    value=c['value'],
                    domain=c.get('domain', 'tonepoet.fans'),
                    path=c.get('path', '/'),
                    secure=c.get('secure', True),
                    expires=c.get('expires')
                )
                user_session.cookies.set_cookie(cookie)
            except Exception as e:
                print(f"Skipping bad stored cookie {c}: {e}")

    return user_session


def update_session_cookies(user_session):
    """Update Flask session with cookies from requests session (including new ones WordPress might set)"""
    if not user_session.cookies:
        return

    # Persist the full cookie metadata, not just name/value
    # This helps keep path-scoped WordPress cookies like wordpress_sec_* intact
    cookie_list = []
    for cookie in user_session.cookies:
        cookie_list.append({
            'name': cookie.name,
            'value': cookie.value,
            'domain': cookie.domain,
            'path': cookie.path,
            'secure': cookie.secure,
            'expires': cookie.expires
        })

    session['forum_cookies'] = cookie_list


def check_auth_required(url=None):
    """Check if authentication is required to access a URL
    Returns: (is_authenticated, error_message)
    - is_authenticated: True if cookies work and page is accessible, False if auth required
    - error_message: None if authenticated, error string if not
    """
    user_session = get_authenticated_session()

    # Use meaningful validation targets for WordPress auth
    # /wp-admin/ is a better validation target than a single hardcoded post URL
    test_urls = []
    if url:
        test_urls.append(url)
    test_urls.extend([
        'https://tonepoet.fans/wp-admin/',
        'https://tonepoet.fans/'
    ])

    wp_logged_in_present = any(
        cookie.name.startswith('wordpress_logged_in_')
        for cookie in user_session.cookies
    )

    print("\n=== AUTH VALIDATION DEBUG ===")
    print(f"Cookies in requests session: {[f'{c.name} (domain={c.domain}, path={c.path})' for c in user_session.cookies]}")
    print(f"Has wordpress_logged_in cookie: {wp_logged_in_present}")

    last_error = None

    for test_url in test_urls:
        try:
            print(f"\nChecking URL: {test_url}")
            response = user_session.get(test_url, timeout=15, allow_redirects=True)

            print(f"  Status: {response.status_code}")
            print(f"  Final URL: {response.url}")
            print(f"  Redirect history: {[r.status_code for r in response.history]}")
            print(f"  Response length: {len(response.text)}")

            # Update Flask session with any new cookies WordPress might have set
            update_session_cookies(user_session)

            final_url = response.url.lower()
            body_lower = response.text.lower()

            # Hard fail only if WordPress clearly redirected us to login
            if 'wp-login.php' in final_url:
                print("  FAIL: Redirected to wp-login.php")
                last_error = 'Cookies are invalid or expired. Redirected to WordPress login.'
                continue

            # If wp-admin is accessible without login redirect, auth is good
            if test_url.endswith('/wp-admin/') and response.status_code == 200 and 'wp-login.php' not in final_url:
                print("  SUCCESS: Reached /wp-admin/ without login redirect")
                return True, None

            # A reachable root page plus a wordpress_logged_in cookie is also good enough
            if test_url == 'https://tonepoet.fans/' and response.status_code == 200 and wp_logged_in_present:
                print("  SUCCESS: Root page reachable and wordpress_logged_in cookie is present")
                return True, None

            # A 404 on one page does not automatically mean the cookies are invalid
            if response.status_code == 404:
                print("  INFO: URL returned 404, trying next validator")
                last_error = f'Validation page returned 404: {test_url}'
                continue

            # Check only for explicit restriction markers
            # Avoid over-triggering on vague text and falsely rejecting valid cookies
            explicit_restriction_markers = [
                'sorry, but you do not have permission to view this content',
                'please register in order to view this'
            ]

            if any(marker in body_lower for marker in explicit_restriction_markers):
                print("  FAIL: Explicit restriction marker found in page body")
                last_error = 'Cookies are invalid or expired. Forum returned a restricted-content message.'
                continue

            # If we got a normal 200 page and have a WordPress login cookie, accept it
            if response.status_code == 200 and wp_logged_in_present:
                print("  SUCCESS: Got HTTP 200 and wordpress_logged_in cookie exists")
                return True, None

            print("  INFO: No success condition matched for this URL")
            last_error = f'Could not confirm authenticated access for {test_url}'

        except Exception as e:
            print(f"  ERROR: Exception while checking {test_url}: {e}")
            last_error = str(e)

    print(f"\nAUTH VALIDATION FAILED: {last_error}")
    return False, last_error or 'Could not validate cookies.'


@app.route('/')
def index():
    """Serve the main HTML page"""
    return send_from_directory('.', 'index.html')


def parse_netscape_cookies(cookie_file_content):
    """Parse Netscape cookie format (from browser extensions like cookies.txt)
    Format: domain\tflag\tpath\tsecure\texpiration\tname\tvalue
    """
    cookies = []

    for line in cookie_file_content.splitlines():
        line = line.strip()

        if not line:
            continue

        if line.startswith('#HttpOnly_'):
            line = line[len('#HttpOnly_'):]
        elif line.startswith('#'):
            # Skip comments
            continue

        # Parse tab-separated values
        parts = line.split('\t')
        if len(parts) < 7:
            continue

        domain = parts[0].strip()
        # flag = parts[1]  # Not currently needed
        path = parts[2].strip() or '/'
        secure = parts[3].strip().upper() == 'TRUE'
        expiration = parts[4].strip()
        name = parts[5].strip()
        value = parts[6].strip()

        # Only include cookies for tonepoet.fans
        if 'tonepoet.fans' not in domain:
            continue

        # Check if cookie is expired (if expiration is not 0 and is in the past)
        expires = None
        if expiration != '0':
            try:
                exp_time = int(expiration)
                if exp_time < time.time():
                    print(f"  Skipping expired cookie: {name}")
                    continue
                expires = exp_time
            except Exception:
                pass

        cookies.append({
            'name': name,
            'value': value,
            'domain': domain,
            'path': path,
            'secure': secure,
            'expires': expires
        })

    return cookies


@app.route('/set-cookies', methods=['POST'])
def set_cookies():
    """Store forum cookies from user's browser session
    Accepts either:
    - JSON with 'cookies' field (text format: "name1=value1; name2=value2")
    - JSON with 'cookieFile' field (Netscape format from browser extension)
    """
    try:
        data = request.get_json(silent=True) or {}

        # Check if it's a file upload (Netscape format)
        if 'cookieFile' in data:
            cookie_file_content = data.get('cookieFile', '')
            if not cookie_file_content:
                return jsonify({'error': 'No cookie file content provided'}), 400

            # Parse Netscape format
            cookies_list = parse_netscape_cookies(cookie_file_content)

            if not cookies_list:
                return jsonify({'error': 'No valid cookies found in file'}), 400

            print(f"\n=== COOKIE FILE PARSED ===")
            print(f"Parsed {len(cookies_list)} cookies from Netscape format:")
            for c in cookies_list:
                print(f"  - {c['name']} (domain={c['domain']}, path={c['path']})")

        # Otherwise, parse as text format
        elif 'cookies' in data:
            cookies_str = data.get('cookies', '')
            if not cookies_str:
                return jsonify({'error': 'No cookies provided'}), 400

            # Parse cookie string (format: "name1=value1; name2=value2")
            # For plain text cookies we have less metadata, so assume root path + secure
            cookies_list = []
            for cookie in cookies_str.split(';'):
                cookie = cookie.strip()
                if '=' in cookie:
                    name, value = cookie.split('=', 1)
                    cookies_list.append({
                        'name': name.strip(),
                        'value': value.strip(),
                        'domain': 'tonepoet.fans',
                        'path': '/',
                        'secure': True,
                        'expires': None
                    })
        else:
            return jsonify({'error': 'No cookies or cookieFile provided'}), 400

        # Store in Flask session
        session['forum_cookies'] = cookies_list
        print(f"Cookies stored in Flask session: {[c['name'] for c in cookies_list]}")

        # Validate cookies using WordPress-aware validation
        is_authenticated, error_message = check_auth_required()

        if not is_authenticated:
            # Remove invalid cookies from session
            session.pop('forum_cookies', None)
            print(f"Cookie validation failed: {error_message}")
            return jsonify({
                'success': False,
                'error': error_message or 'Cookies are invalid or expired. Please log in again and export fresh cookies.'
            }), 400

        print("Cookie validation succeeded")
        return jsonify({
            'success': True,
            'message': f'Cookies saved and validated successfully ({len(cookies_list)} cookies)'
        })
    except Exception as e:
        print(f"Error saving cookies: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/auth-status', methods=['GET'])
def auth_status():
    """Check if user has uploaded cookies"""
    has_cookies = 'forum_cookies' in session
    cookie_count = len(session.get('forum_cookies', []))

    return jsonify({
        'loggedIn': has_cookies and cookie_count > 0,
        'cookieCount': cookie_count,
        'error': None if (has_cookies and cookie_count > 0) else 'No cookies uploaded'
    })


# Real-Debrid API Integration (Token-based)

@app.route('/realdebrid/status', methods=['GET'])
def realdebrid_status():
    """Check Real-Debrid connection status and validate token"""
    token = session.get('realdebrid_token')
    if not token:
        return jsonify({
            'connected': False,
            'error': 'No token stored'
        })

    # Validate token by making a simple API call
    try:
        headers = {
            'Authorization': f'Bearer {token}'
        }
        response = requests.get(f"{REAL_DEBRID_API_BASE}/user", headers=headers, timeout=10)
        if response.status_code == 401:
            # Token is invalid, clear it
            session.pop('realdebrid_token', None)
            return jsonify({
                'connected': False,
                'error': 'Token is invalid or expired'
            })
        response.raise_for_status()
        return jsonify({
            'connected': True,
            'username': response.json().get('username', 'Unknown')
        })
    except Exception as e:
        print(f"Error checking Real-Debrid status: {e}")
        return jsonify({
            'connected': False,
            'error': str(e)
        })


@app.route('/realdebrid/set-token', methods=['POST'])
def realdebrid_set_token():
    """Store Real-Debrid API token from user"""
    data = request.get_json() or {}
    token = data.get('token', '').strip()

    if not token:
        return jsonify({'error': 'Token is required'}), 400

    # Validate token by making a test API call
    try:
        headers = {
            'Authorization': f'Bearer {token}'
        }
        response = requests.get(f"{REAL_DEBRID_API_BASE}/user", headers=headers, timeout=10)
        if response.status_code == 401:
            return jsonify({'error': 'Invalid token. Please check your token from https://real-debrid.com/apitoken'}), 400
        response.raise_for_status()

        # Token is valid, store it
        session['realdebrid_token'] = token
        user_data = response.json()
        return jsonify({
            'success': True,
            'username': user_data.get('username', 'Unknown'),
            'message': 'Token saved successfully'
        })
    except requests.exceptions.RequestException as e:
        print(f"Error validating Real-Debrid token: {e}")
        return jsonify({'error': f'Failed to validate token: {str(e)}'}), 500
    except Exception as e:
        print(f"Error setting Real-Debrid token: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/realdebrid/unrestrict', methods=['POST'])
def realdebrid_unrestrict():
    """Unrestrict a link via Real-Debrid"""
    token = session.get('realdebrid_token')
    if not token:
        return jsonify({'error': 'Real-Debrid not connected. Please enter your API token first.'}), 401

    data = request.get_json() or {}
    original_link = data.get('link')
    if not original_link:
        return jsonify({'error': 'Link parameter is required'}), 400

    try:
        headers = {
            'Authorization': f'Bearer {token}'
        }
        payload = {
            'link': original_link
        }
        response = requests.post(f"{REAL_DEBRID_API_BASE}/unrestrict/link", data=payload, headers=headers, timeout=30)

        if response.status_code == 401:
            # Token might be invalid, clear it
            session.pop('realdebrid_token', None)
            return jsonify({'error': 'Real-Debrid token expired or invalid. Please reconnect.'}), 401

        if response.status_code != 200:
            try:
                error_data = response.json()
                error_message = error_data.get('error', f"Real-Debrid error (HTTP {response.status_code})")
            except ValueError:
                error_message = f"Real-Debrid error (HTTP {response.status_code})"
            return jsonify({'error': error_message}), response.status_code

        result = response.json()
        unrestricted_link = result.get('download')
        if not unrestricted_link:
            return jsonify({'error': 'Real-Debrid did not return a download link.'}), 500

        return jsonify({
            'download': unrestricted_link,
            'filename': result.get('filename'),
            'filesize': result.get('filesize'),
            'host': result.get('host'),
            'id': result.get('id'),
            'original': original_link
        })
    except requests.exceptions.RequestException as e:
        print(f"Real-Debrid request failed: {e}")
        return jsonify({'error': 'Failed to contact Real-Debrid API. Please try again.'}), 500
    except Exception as e:
        print(f"Error in Real-Debrid unrestrict: {e}")
        return jsonify({'error': str(e)}), 500


def scrape_search_results(query):
    """Scrape the forum search results page and extract post information
    Returns tuple: (posts, requires_auth) where requires_auth is True if login is needed"""
    search_url = f"{BASE_URL}/?s={quote_plus(query)}"

    # Use authenticated session with user's cookies
    user_session = get_authenticated_session()

    try:
        response = user_session.get(search_url, timeout=10, allow_redirects=True)
        response.raise_for_status()

        # Update Flask session with any new cookies WordPress might have set
        update_session_cookies(user_session)

        # Debug: Log response info
        print(f"Response status: {response.status_code}")
        print(f"Response URL: {response.url}")
        print(f"Response length: {len(response.text)} bytes")
        print(f"Cookies in request: {[cookie.name for cookie in user_session.cookies]}")

        soup = BeautifulSoup(response.content, 'lxml')

        # First-post authentication check: if the first post body shows restricted message, require login
        try:
            first_post_elem = None
            tentative_posts = soup.find_all(['article', 'div'], class_=lambda x: x and ('post' in x.lower() or 'entry' in x.lower()))
            if tentative_posts:
                first_post_elem = tentative_posts[0]
            else:
                first_heading = soup.find('h2')
                if first_heading:
                    first_post_elem = first_heading.find_parent(['article', 'div']) or first_heading
            if first_post_elem is not None:
                first_post_html = str(first_post_elem).lower()
                if ('members-access-error' in first_post_html) or ('sorry, but you do not have permission to view this content' in first_post_html):
                    print("Authentication required: first post is restricted")
                    return [], True
        except Exception:
            # Non-fatal: continue with other detection methods
            pass

        # Check if authentication is required
        # Look for common login page indicators
        page_text = soup.get_text().lower()
        page_html = str(soup).lower()
        page_title = soup.find('title')
        title_text = page_title.get_text().lower() if page_title else ''

        # Check for the exact permission error text or partial matches
        response_text = response.text
        response_lower = response_text.lower()

        # Check for various forms of the permission error
        permission_indicators = [
            'sorry, but you do not have permission to view this content',
            'do not have permission to view this content',
            'please register in order to view this',
            'members-access-error'
        ]

        for indicator in permission_indicators:
            if indicator in response_lower:
                print(f"Authentication required: found '{indicator}'")
                return [], True

        # Try multiple ways to find it in parsed soup
        members_error_div = (
            soup.find('div', class_='members-access-error') or
            soup.find('div', class_=lambda x: x and 'members-access-error' in str(x) if x else False)
        )
        if members_error_div:
            print("Authentication required: found members-access-error div")
            return [], True

        # Check for login page indicators
        login_indicators = [
            'wp-login.php' in response.url.lower(),
            'log in' in title_text,
            'login' in title_text and 'required' in page_text,
            soup.find('form', {'id': 'loginform'}),
            soup.find('form', {'name': 'loginform'}),
            'you must be logged in' in page_text,
            'please log in' in page_text,
            'login required' in page_text,
            'you do not have permission to view this content' in page_text,
            'members-access-error' in page_html,
            'please register in order to view this' in page_text,
            'do not have permission' in page_text
        ]

        requires_auth = any(login_indicators)

        if requires_auth:
            print(f"Authentication required detected for query: {query}")
            return [], True

        posts = []

        # Find all post entries in search results
        # Look for divs with id="post-XXXX" pattern (actual search result posts)
        # Or h2.entry-title elements (post titles in search results)

        # Method 1: Find divs with post-XXXX id pattern
        post_elements = soup.find_all('div', id=lambda x: x and x.startswith('post-'))

        # Method 2: If that doesn't work, find h2.entry-title elements
        if not post_elements:
            entry_titles = soup.find_all('h2', class_='entry-title')
            for h2 in entry_titles:
                # Find the parent post div
                parent_post = h2.find_parent('div', id=lambda x: x and x.startswith('post-'))
                if parent_post:
                    post_elements.append(parent_post)

        # Check if all posts have restricted content
        restricted_posts_count = 0
        total_posts_found = 0

        for post_elem in post_elements:
            # Find the h2.entry-title link inside this post
            entry_title = post_elem.find('h2', class_='entry-title')
            if entry_title:
                link = entry_title.find('a')
                if link:
                    total_posts_found += 1
                    post_url = urljoin(BASE_URL, link.get('href', ''))
                    post_title = link.get_text(strip=True) or link.get('title', '')

                    # Check if this post has restricted content
                    if post_elem.find('div', class_=lambda x: x and 'members-access-error' in str(x).lower() if x else False):
                        restricted_posts_count += 1

                    # Try to find date nearby
                    date_elem = post_elem.find(['time', 'span'], class_=lambda x: x and 'date' in x.lower() if x else False)
                    post_date = date_elem.get_text(strip=True) if date_elem else ''

                    posts.append({
                        'title': post_title,
                        'url': post_url,
                        'date': post_date
                    })

        # If we found posts but all of them are restricted, require authentication
        # Also check if any posts have restricted content - if most/all do, require auth
        if total_posts_found > 0:
            print(f"Found {total_posts_found} posts, {restricted_posts_count} are restricted")
            if restricted_posts_count == total_posts_found:
                print(f"All {total_posts_found} posts are restricted - authentication required")
                return [], True
            # If more than half the posts are restricted, likely need auth
            elif restricted_posts_count > 0 and (restricted_posts_count / total_posts_found) >= 0.5:
                print(f"{restricted_posts_count}/{total_posts_found} posts are restricted - authentication likely required")
                return [], True

        print(f"Returning {len(posts)} posts, auth not required")
        return posts, False
    except Exception as e:
        print(f"Error scraping search results: {e}")
        return [], False


def looks_like_download_link(url, text):
    """Check whether a link looks like an off-site download/mirror link"""
    url_l = (url or '').lower()
    text_l = (text or '').lower()

    # Ignore forum/internal/social links
    bad_domains = [
        'tonepoet.fans',
        'facebook.com',
        'twitter.com',
        'x.com',
        'instagram.com',
        'youtube.com',
        'youtu.be'
    ]
    if any(domain in url_l for domain in bad_domains):
        return False

    # Known file host / mirror patterns seen on these kinds of pages
    good_patterns = [
        'ddownload.com',
        'hexload',
        'rapidgator',
        'nitroflare',
        'katfile',
        'uploadgig',
        'turbobit',
        'fikper',
        '1dl.net',
        'clicknupload',
        'drop.download',
        'filecrypt',
        'multiup',
        'mega.nz',
        'mediafire',
        'pixeldrain',
        'drive.google.com',
        '/go/',
        '/download',
        'download'
    ]

    if any(pattern in url_l for pattern in good_patterns):
        return True

    if any(pattern in text_l for pattern in ['download', 'mirror', 'link', 'links']):
        return True

    return False


def scrape_post_album_links(post_url, query):
    """Scrape a single post page to extract album download links"""
    # Use authenticated session with user's cookies
    user_session = get_authenticated_session()

    try:
        response = user_session.get(post_url, timeout=10, allow_redirects=True)
        response.raise_for_status()

        # Update Flask session with any new cookies WordPress might have set
        update_session_cookies(user_session)

        print(f"  Post fetch status: {response.status_code}")
        print(f"  Post final URL: {response.url}")
        print(f"  Post length: {len(response.text)} bytes")

        body_lower = response.text.lower()

        # If the post page itself is restricted, signal that back to the search endpoint
        if 'sorry, but you do not have permission to view this content' in body_lower or 'members-access-error' in body_lower:
            print("  Post is explicitly restricted")
            return [], True

        soup = BeautifulSoup(response.content, 'lxml')

        album_links = []

        # Find ALL links on the page - no need to find specific divs
        all_links = soup.find_all('a', href=True)
        print(f"  Total <a> links found on page: {len(all_links)}")

        query_terms = [t for t in query.lower().split() if len(t) >= 3]
        candidate_links = []

        for link in all_links:
            link_url = link.get('href', '').strip()
            link_text = link.get_text(" ", strip=True)

            if not link_url:
                continue

            # Make sure URL is absolute
            full_url = urljoin(BASE_URL, link_url)

            # Filter: keep only links that look like download/mirror links
            if not looks_like_download_link(full_url, link_text):
                continue

            # Score links by how many query terms appear in the URL/text
            relevance_score = 0
            haystack = f"{link_text} {full_url}".lower()
            for term in query_terms:
                if term in haystack:
                    relevance_score += 1

            candidate_links.append({
                'text': link_text or full_url,
                'url': full_url,
                'score': relevance_score,
                'host': urlparse(full_url).netloc.lower()
            })

        print(f"  Candidate download links found: {len(candidate_links)}")
        for item in candidate_links[:10]:
            print(f"    - [{item['score']}] {item['host']} :: {item['text'][:120]}")

        # Prefer query-relevant links, but don't require a strict text match
        candidate_links.sort(key=lambda x: (x['score'], x['host'], x['text']), reverse=True)

        # Deduplicate by URL
        seen = set()
        for item in candidate_links:
            if item['url'] in seen:
                continue
            seen.add(item['url'])
            album_links.append({
                'text': item['text'],
                'url': item['url']
            })

        return album_links, False
    except Exception as e:
        print(f"Error scraping post {post_url}: {e}")
        import traceback
        traceback.print_exc()
        return [], False


def format_date(date_str):
    """Format date string to consistent format (e.g., 'September 2025')"""
    if not date_str:
        return ''

    # Try to extract month and year from various date formats
    # Look for patterns like "April 14, 2025" or "September 2025"
    date_str = date_str.strip()

    # Pattern for "Month Day, Year" or "Month Year"
    month_year_pattern = r'([A-Za-z]+)\s+(\d{4})'
    match = re.search(month_year_pattern, date_str)
    if match:
        month = match.group(1)
        year = match.group(2)
        return f"{month} {year}"

    return date_str


@app.route('/search', methods=['GET'])
def search():
    """Search endpoint for forum queries"""
    query = request.args.get('q', '')

    if not query:
        return jsonify({'error': 'Query parameter is required'}), 400

    # Debug: Check if cookies are stored
    has_cookies = 'forum_cookies' in session
    print(f"\n=== SEARCH DEBUG for '{query}' ===")
    print(f"Has stored cookies: {has_cookies}")
    if has_cookies:
        stored = session['forum_cookies']
        if isinstance(stored, list):
            print(f"Cookie names: {[c['name'] for c in stored]}")
        elif isinstance(stored, dict):
            print(f"Cookie names: {list(stored.keys())}")

    try:
        # Scrape search results
        posts, requires_auth = scrape_search_results(query)

        print(f"Requires auth: {requires_auth}")
        print(f"Posts found: {len(posts)}")
        if posts:
            print("Posts detected:")
            for i, post in enumerate(posts, 1):
                print(f"  {i}. {post['title']} ({post['url']})")

        if requires_auth:
            return jsonify({
                'results': [],
                'requiresAuth': True,
                'message': 'Please log in to the forum to search',
                'debug': {
                    'hasCookies': has_cookies,
                    'cookieCount': len(session.get('forum_cookies', []))
                }
            })

        if not posts:
            return jsonify({
                'results': [],
                'message': 'No posts found for this query',
                'debug': {
                    'hasCookies': has_cookies,
                    'cookieCount': len(session.get('forum_cookies', [])),
                    'requiresAuth': requires_auth
                }
            })

        # Scrape each post for album links
        results = []
        any_restricted_posts = False

        for post in posts:
            try:
                print(f"\nProcessing post: {post['title']}")
                album_links, post_restricted = scrape_post_album_links(post['url'], query)
                any_restricted_posts = any_restricted_posts or post_restricted
                print(f"  Found {len(album_links)} candidate links in this post")
                post_date = format_date(post['date'])

                for link in album_links:
                    results.append({
                        'album': link['text'],
                        'url': link['url'],
                        'postTitle': post['title'],
                        'postUrl': post['url'],
                        'postDate': post_date
                    })

                # Add small delay to avoid overwhelming the server
                time.sleep(0.5)
            except Exception as e:
                print(f"Error processing post {post['url']}: {e}")
                continue

        # Only require auth if posts/pages explicitly showed restricted content
        if any_restricted_posts and len(results) == 0:
            return jsonify({
                'results': [],
                'requiresAuth': True,
                'message': 'Search results were found, but the post content appears restricted. Please refresh cookies.',
                'debug': {
                    'postsFound': len(posts),
                    'albumLinksFound': 0,
                    'hasCookies': has_cookies
                }
            })

        # No results is just no results, not an auth failure
        if len(results) == 0:
            print("No candidate download links found, but authentication appears OK")
            return jsonify({
                'results': [],
                'message': 'No matching download links were found in the matching posts.',
                'debug': {
                    'postsFound': len(posts),
                    'albumLinksFound': 0,
                    'hasCookies': has_cookies,
                    'requiresAuth': False
                }
            })

        print(f"Successfully found {len(results)} album links")
        return jsonify({
            'results': results,
            'debug': {
                'postsFound': len(posts),
                'albumLinksFound': len(results),
                'hasCookies': has_cookies
            }
        })
    except Exception as e:
        error_msg = str(e)
        print(f"Error in search endpoint: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'An error occurred while searching: {error_msg}', 'results': []}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug, port=port)