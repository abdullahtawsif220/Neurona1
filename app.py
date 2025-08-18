from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
import secrets
import re
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
DB_NAME = "users.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


# Creation of tables(users, ideas) if not already present in project file
def init_db():
    if not os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                verified INTEGER DEFAULT 0,
                full_name TEXT,
                phone TEXT,
                gov_id TEXT,
                linkedin_id TEXT,
                present_address TEXT
            )
        ''')
        c.execute('''
                    CREATE TABLE ideas (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       creator_id INTEGER NOT NULL,
                       title TEXT NOT NULL,
                       category TEXT NOT NULL,
                       tags TEXT,
                       stage TEXT DEFAULT 'Idea',
                       industry TEXT,
                       summary TEXT,
                       description TEXT,
                       funding_needed REAL,
                       equity_offered REAL,
                       pitch_deck TEXT,
                       contact_email TEXT,
                       product_image TEXT,
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       FOREIGN KEY (creator_id) REFERENCES users(id)
                   )
               ''')
        c.execute('''
            CREATE TABLE investment_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investor_id INTEGER NOT NULL,
                creator_id INTEGER NOT NULL,
                idea_id INTEGER NOT NULL,
                investment_amount REAL NOT NULL,
                status TEXT DEFAULT 'pending',
                message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (investor_id) REFERENCES users(id),
                FOREIGN KEY (creator_id) REFERENCES users(id),
                FOREIGN KEY (idea_id) REFERENCES ideas(id)
            )
        ''')
        c.execute('''
            CREATE TABLE notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                type TEXT DEFAULT 'info',
                is_read INTEGER DEFAULT 0,
                related_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        # Add wallet_transactions table
        c.execute('''
            CREATE TABLE wallet_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                type TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        admin_email = "admin@neurona.com"
        admin_password = "admin@123"
        hashed_pw = generate_password_hash(admin_password)
        c.execute("INSERT INTO users (username, email, password, role, verified) VALUES (?, ?, ?, ?, ?)",
                  ("Admin", admin_email, hashed_pw, "admin", 1))
        conn.commit()
        conn.close()
        print(f" Admin created: {admin_email} / {admin_password}")

    # Check and add wallet_balance column if it doesn't exist
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("PRAGMA table_info(users)")
    columns = [col['name'] for col in c.fetchall()]
    if 'wallet_balance' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN wallet_balance REAL DEFAULT 0.0")
        conn.commit()
    conn.close()


@app.route('/')
def home():
    return render_template('index.html')


# Registration logic
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()
        confirm_password = request.form['confirm_password'].strip()
        role = request.form['role']

        if not username or not email or not password or not confirm_password or not role:
            flash('Please fill all fields.', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        allowed_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "neurona.com"]
        email_domain = email.split('@')[-1].lower()
        if email_domain not in allowed_domains:
            flash(f"Email domain must be one of: {', '.join(allowed_domains)}", 'danger')
            return redirect(url_for('register'))

        if len(password) < 8 or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            flash('Password must be at least 8 characters and include a special character.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users(username, email, password, role) VALUES (?, ?, ?, ?)",
                      (username, email, hashed_password, role))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists.', 'danger')
            return redirect(url_for('register'))
        finally:
            conn.close()

    return render_template('register.html')

# Login logic
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=?", (email,))
        user = c.fetchone()
        conn.close()

        if user:
            stored_hash = user['password']
            if check_password_hash(stored_hash, password):
                session['username'] = user['username']
                session['email'] = user['email']
                session['role'] = user['role']
                session['verified'] = user['verified']
                session['user_id'] = user['id']
                return redirect(url_for(f"{user['role']}_dashboard"))
            else:
                flash('Incorrect password.', 'danger')
        else:
            flash('Invalid email.', 'danger')

        return redirect(url_for('login'))

    return render_template('login.html')


##  --------------------------------------- CREATOR LOGIC STARTS FROM HERE ----------------------------------------- ##

# main creator dashboard
@app.route('/creator_dashboard')
def creator_dashboard():
    if 'username' in session and session.get('role') == 'creator':
        conn = get_db_connection()
        user = conn.execute("SELECT verified FROM users WHERE email = ?", (session['email'],)).fetchone()

        # Fetch creator's own ideas
        creator_ideas = conn.execute('''
            SELECT 
                id, 
                title, 
                category, 
                summary, 
                industry,
                funding_needed,
                equity_offered,
                contact_email,
                product_image,
                created_at
            FROM ideas 
            WHERE creator_id = ?
            ORDER BY created_at DESC
        ''', (session['user_id'],)).fetchall()

        conn.close()
        verified = user['verified'] if user else 0
        # Update session so you keep the verified status too
        session['verified'] = verified
        return render_template('creator_dashboard.html', username=session['username'], verified=verified,
                               creator_ideas=creator_ideas)

    return redirect(url_for('login'))


#verification request sent by creator
@app.route('/creator/verify', methods=['GET', 'POST'])
def verify_creator():
    if 'role' not in session or session['role'] != 'creator':
        return redirect(url_for('login'))

    if request.method == 'POST':
        full_name = request.form['full_name'].strip()
        phone = request.form['phone'].strip()
        gov_id = request.form['gov_id'].strip()
        linkedin_id = request.form['linkedin_id'].strip()
        present_address = request.form['present_address'].strip()

        conn = get_db_connection()

        # --- NEW LOGIC START ---
        # Fetch the current verified status of the user
        current_user = conn.execute("SELECT verified FROM users WHERE email = ?", (session['email'],)).fetchone()

        # If the user was previously declined (verified = 2),
        # set their status back to pending (0) upon re-submission.
        # Otherwise, keep it as it was (likely 0 if initial submission).
        new_verified_status = 0  # Default to pending upon submission
        if current_user and current_user['verified'] == 1:
            # If they were already verified, don't change it to pending
            new_verified_status = 1
        # --- NEW LOGIC END ---

        conn.execute('''
            UPDATE users SET full_name=?, phone=?, gov_id=?, linkedin_id=?, present_address=?, verified=?
            WHERE email=?
        ''', (full_name, phone, gov_id, linkedin_id, present_address, new_verified_status, session['email']))
        conn.commit()
        conn.close()

        flash('Verification request submitted. Wait for admin approval.', 'info')
        # Update the session with the new status immediately
        session['verified'] = new_verified_status
        return redirect(url_for('creator_dashboard'))

    return render_template('verify_creator.html', email=session['email'])


#logic of uploading ideas by a creator
@app.route('/creator/upload_idea')
def upload_idea():
    if 'role' not in session or session['role'] != 'creator':
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute('SELECT verified FROM users WHERE email = ?', (session['email'],)).fetchone()
    conn.close()

    if user and user['verified'] == 1:
        return redirect(url_for('submit_idea'))  # your actual submission route
    else:
        flash('Please verify yourself before uploading an idea.', 'warning')
        return redirect(url_for('verify_creator'))


# creator submit ideas logic
@app.route('/submit_idea', methods=['GET', 'POST'])
def submit_idea():
    if 'username' not in session or session['role'] != 'creator':
        flash('Only creators can submit ideas.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        category = request.form['category']
        tags = request.form.get('tags', '')
        stage = request.form.get('stage', 'Idea')
        industry = request.form.get('industry')
        summary = request.form.get('summary')
        description = request.form.get('description')
        funding = request.form.get('funding_needed', type=float)
        equity = request.form.get('equity_offered', type=float)
        contact_email = request.form.get('contact_email')

        # Handle file uploads
        product_image = request.files.get('product_image')
        product_image_filename = None

        if product_image and product_image.filename:
            import os
            from werkzeug.utils import secure_filename

            # Create uploads directory if it doesn't exist
            upload_dir = os.path.join('static', 'uploads')
            if not os.path.exists(upload_dir):
                os.makedirs(upload_dir)

            # Save the product image
            filename = secure_filename(product_image.filename)
            # Add timestamp to avoid filename conflicts
            import time
            timestamp = str(int(time.time()))
            name, ext = os.path.splitext(filename)
            product_image_filename = f"{name}_{timestamp}{ext}"
            product_image.save(os.path.join(upload_dir, product_image_filename))

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email = ?", (session['email'],))
        creator = c.fetchone()

        if creator:
            creator_id = creator['id']
            c.execute('''
                INSERT INTO ideas (
                    creator_id, title, category, tags, stage, industry, summary, description,
                    funding_needed, equity_offered, contact_email, product_image
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (creator_id, title, category, tags, stage, industry, summary, description, funding, equity,
                  contact_email, product_image_filename))
            conn.commit()
            conn.close()
            flash('Idea submitted successfully!', 'success')
            return redirect(url_for('creator_dashboard'))
        else:
            conn.close()
            flash('Creator not found.', 'danger')
            return redirect(url_for('submit_idea'))

    return render_template('submit_idea.html')



# creator ideas details logic
@app.route('/creator/ideas/<int:idea_id>')
def creator_idea_details(idea_id):
    # Check if the user is logged in and is a creator
    if 'username' not in session or session.get('role') != 'creator':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    # Fetch the idea, ensuring it belongs to the current user
    idea = conn.execute('''
        SELECT 
            id, 
            title, 
            category, 
            tags,
            stage,
            summary, 
            description,
            funding_needed,
            equity_offered,
            product_image
        FROM ideas 
        WHERE id = ? AND creator_id = ?
    ''', (idea_id, session['user_id'])).fetchone()
    conn.close()

    if not idea:
        flash('Idea not found or you do not have permission to view it.', 'danger')
        return redirect(url_for('creator_dashboard'))

    return render_template('creator_idea_details.html', idea=idea)


#  Delete an idea(creator's idea)
@app.route('/creator/ideas/delete/<int:idea_id>', methods=['POST'])
def delete_creator_idea(idea_id):
    # Ensure the user is a creator and is logged in
    if 'user_id' not in session or session.get('role') != 'creator':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    try:
        # First, check if the idea belongs to the logged-in user
        idea = conn.execute('SELECT creator_id FROM ideas WHERE id = ?', (idea_id,)).fetchone()

        if idea is None or idea['creator_id'] != session['user_id']:
            flash('You do not have permission to delete this idea.', 'danger')
            return redirect(url_for('creator_dashboard'))

        # If the user is the owner, proceed with deletion
        conn.execute('DELETE FROM ideas WHERE id = ?', (idea_id,))
        conn.commit()
        flash('Idea deleted successfully.', 'success')

    except sqlite3.Error as e:
        flash(f'An error occurred: {e}', 'danger')
    finally:
        conn.close()

    return redirect(url_for('creator_dashboard'))


# Creator investment requests page
@app.route('/creator/investment_requests')
def creator_investment_requests():
    if 'user_id' not in session or session.get('role') != 'creator':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    pending_requests = conn.execute('''
        SELECT ir.*, i.title, i.summary, i.product_image, u.username as investor_name, u.email as investor_email
        FROM investment_requests ir
        JOIN ideas i ON ir.idea_id = i.id
        JOIN users u ON ir.investor_id = u.id
        WHERE ir.creator_id = ? AND ir.status = 'pending'
        ORDER BY ir.created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    
    return render_template('creator_investment_requests.html', 
                         pending_requests=pending_requests,
                         username=session.get('username'))


# Handle investment request decision (approve/decline)
@app.route('/creator/investment_request/<int:request_id>/<action>')
def handle_investment_request(request_id, action):
    if 'user_id' not in session or session.get('role') != 'creator':
        return redirect(url_for('login'))
    
    if action not in ['approve', 'decline']:
        flash('Invalid action.', 'danger')
        return redirect(url_for('creator_investment_requests'))
    
    conn = get_db_connection()
    
    # Get request details
    request_details = conn.execute('''
        SELECT ir.*, i.title, u.username as investor_name
        FROM investment_requests ir
        JOIN ideas i ON ir.idea_id = i.id
        JOIN users u ON ir.investor_id = u.id
        WHERE ir.id = ? AND ir.creator_id = ?
    ''', (request_id, session['user_id'])).fetchone()
    
    if not request_details:
        flash('Investment request not found.', 'danger')
        conn.close()
        return redirect(url_for('creator_investment_requests'))
    
    # Update request status
    new_status = 'approved' if action == 'approve' else 'declined'
    conn.execute('''
        UPDATE investment_requests 
        SET status = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    ''', (new_status, request_id))
    
    # Create notification for investor
    if action == 'approve':
        notification_title = "Investment Request Approved"
        notification_message = f"Your investment request for '{request_details['title']}' has been approved! Proceed to payment & agreement."
        notification_type = 'success'
    else:
        notification_title = "Investment Request Declined"
        notification_message = f"Your investment request for '{request_details['title']}' has been declined by the creator."
        notification_type = 'info'
    
    conn.execute('''
        INSERT INTO notifications (user_id, title, message, type, related_id)
        VALUES (?, ?, ?, ?, ?)
    ''', (request_details['investor_id'], notification_title, notification_message, notification_type, request_details['idea_id']))
    
    conn.commit()
    conn.close()
    
    action_text = 'approved' if action == 'approve' else 'declined'
    flash(f'Investment request {action_text} successfully!', 'success')
    return redirect(url_for('creator_investment_requests'))


#route for creator wallet
@app.route('/creator_wallet')
def creator_wallet():
    return render_template('creator_wallet.html')



## ---------------------------------- INVESTOR LOGIC STARTS FROM HERE ------------------------------------------- ##


# main investor dashboard logic
@app.route('/investor_dashboard')
def investor_dashboard():
    if 'username' in session and session.get('role') == 'investor':
        conn = get_db_connection()
        user = conn.execute("SELECT verified FROM users WHERE email = ?", (session['email'],)).fetchone()

        # Get real-time count of pending investments
        # NEW CODE START
        pending_count = conn.execute('''
            SELECT COUNT(*) as count FROM investment_requests
            WHERE investor_id = ? AND status = 'pending'
        ''', (session['user_id'],)).fetchone()['count']
        # NEW CODE END
        
        # Get search and filter parameters
        search_query = request.args.get('search', '').strip()
        category_filter = request.args.get('category', '').strip()
        stage_filter = request.args.get('stage', '').strip()

        # Build the SQL query with filters
        base_query = '''
            SELECT
                i.id,
                i.title,
                i.category,
                i.tags,
                i.stage,
                i.summary,
                i.industry,
                i.funding_needed,
                i.equity_offered,
                i.contact_email,
                i.product_image,
                i.created_at,
                u.username
            FROM ideas i
            JOIN users u ON i.creator_id = u.id
            WHERE 1=1
        '''

        params = []

        # Add search filter
        if search_query:
            base_query += " AND (i.title LIKE ? OR i.category LIKE ? OR i.tags LIKE ?)"
            search_param = f"%{search_query}%"
            params.extend([search_param, search_param, search_param])

        # Add category filter
        if category_filter and category_filter != 'All Categories':
            base_query += " AND i.category = ?"
            params.append(category_filter)

        # Add stage filter
        if stage_filter and stage_filter != 'All Stages':
            base_query += " AND i.stage = ?"
            params.append(stage_filter)

        base_query += " ORDER BY i.created_at DESC"

        # Fetch all ideas for investment opportunities
        ideas = conn.execute(base_query, params).fetchall()

        # Get unique categories and stages for filter dropdowns
        categories = conn.execute(
            "SELECT DISTINCT category FROM ideas WHERE category IS NOT NULL ORDER BY category").fetchall()
        stages = conn.execute("SELECT DISTINCT stage FROM ideas WHERE stage IS NOT NULL ORDER BY stage").fetchall()

        conn.close()
        verified = user['verified'] if user else 0
        # Update session so you keep the verified status too
        session['verified'] = verified
        return render_template('investor_dashboard.html',
                               username=session['username'],
                               verified=verified,
                               ideas=ideas,
                               categories=categories,
                               stages=stages,
                               current_search=search_query,
                               current_category=category_filter,
                               current_stage=stage_filter,
                               pending_count=pending_count) # NEW: Pass pending_count to the template
    return redirect(url_for('login'))


# verification request sent by investor
@app.route('/investor/verify', methods=['GET', 'POST'])
def verify_investor():
    if 'role' not in session or session['role'] != 'investor':
        return redirect(url_for('login'))

    if request.method == 'POST':
        full_name = request.form['full_name'].strip()
        phone = request.form['phone'].strip()
        gov_id = request.form['gov_id'].strip()
        linkedin_id = request.form['linkedin_id'].strip()
        present_address = request.form['present_address'].strip()

        conn = get_db_connection()

        # Fetch the current verified status of the user
        current_user = conn.execute("SELECT verified FROM users WHERE email = ?", (session['email'],)).fetchone()

        # If the user was previously declined (verified = 2),
        # set their status back to pending (0) upon re-submission.
        # Otherwise, keep it as it was (likely 0 if initial submission).
        new_verified_status = 0  # Default to pending upon submission
        if current_user and current_user['verified'] == 1:
            # If they were already verified, don't change it to pending
            new_verified_status = 1
        # --- NEW LOGIC END ---

        conn.execute('''
           UPDATE users SET full_name=?, phone=?, gov_id=?, linkedin_id=?, present_address=?, verified=?
           WHERE email=?
            ''', (full_name, phone, gov_id, linkedin_id, present_address, new_verified_status, session['email']))
        conn.commit()
        conn.close()

        flash('Verification request submitted. Wait for admin approval.', 'info')
        # Update the session with the new status immediately
        session['verified'] = new_verified_status
        return redirect(url_for('investor_dashboard'))

    return render_template('verify_investor.html', email=session['email'])




# Idea details page for investors
@app.route('/idea/<int:idea_id>')
def idea_details(idea_id):
    if 'username' not in session or session.get('role') != 'investor':
        return redirect(url_for('login'))

    # Check if investor is verified
    if session.get('verified') != 1:
        flash('Please verify your account to view idea details.', 'warning')
        return redirect(url_for('investor_dashboard'))

    conn = get_db_connection()
    idea = conn.execute('''
        SELECT 
            i.id, 
            i.title, 
            i.category, 
            i.tags,
            i.stage,
            i.summary, 
            i.description,
            i.industry,
            i.funding_needed,
            i.equity_offered,
            i.contact_email,
            i.product_image,
            i.created_at,
            u.username,
            u.full_name
        FROM ideas i 
        JOIN users u ON i.creator_id = u.id
        WHERE i.id = ?
    ''', (idea_id,)).fetchone()

    conn.close()

    if not idea:
        flash('Idea not found.', 'danger')
        return redirect(url_for('investor_dashboard'))

    return render_template('idea_details.html', idea=idea)


# Investment request submission
@app.route('/submit_investment_request/<int:idea_id>', methods=['POST'])
def submit_investment_request(idea_id):
    if 'user_id' not in session or session.get('role') != 'investor':
        flash('Please login as an investor to submit investment requests.', 'danger')
        return redirect(url_for('login'))
    
    if session.get('verified') != 1:
        flash('Please verify your account before submitting investment requests.', 'warning')
        return redirect(url_for('investor_dashboard'))
    
    investment_amount = request.form.get('investment_amount', type=float)
    message = request.form.get('message', '').strip()
    
    if not investment_amount or investment_amount <= 0:
        flash('Please enter a valid investment amount.', 'danger')
        return redirect(url_for('idea_details', idea_id=idea_id))
    
    conn = get_db_connection()
    
    # Get idea and creator info
    idea = conn.execute('''
        SELECT i.*, u.username as creator_name 
        FROM ideas i 
        JOIN users u ON i.creator_id = u.id 
        WHERE i.id = ?
    ''', (idea_id,)).fetchone()
    
    if not idea:
        flash('Idea not found.', 'danger')
        conn.close()
        return redirect(url_for('investor_dashboard'))
    
    # Check if investor already has a pending request for this idea
    existing_request = conn.execute('''
        SELECT id FROM investment_requests 
        WHERE investor_id = ? AND idea_id = ? AND status = 'pending'
    ''', (session['user_id'], idea_id)).fetchone()
    
    if existing_request:
        flash('You already have a pending investment request for this idea.', 'warning')
        conn.close()
        return redirect(url_for('idea_details', idea_id=idea_id))
    
    # Create investment request
    conn.execute('''
        INSERT INTO investment_requests (investor_id, creator_id, idea_id, investment_amount, message)
        VALUES (?, ?, ?, ?, ?)
    ''', (session['user_id'], idea['creator_id'], idea_id, investment_amount, message))
    
    # Create notification for creator
    investor_name = session.get('username', 'An investor')
    notification_title = "New Investment Request"
    notification_message = f"{investor_name} wants to invest BDT {investment_amount:,.0f} in your idea '{idea['title']}'"
    
    conn.execute('''
        INSERT INTO notifications (user_id, title, message, type, related_id)
        VALUES (?, ?, ?, ?, ?)
    ''', (idea['creator_id'], notification_title, notification_message, 'investment_request', idea_id))
    
    conn.commit()
    conn.close()
    
    flash('Investment request submitted successfully! The creator will review your request.', 'success')
    return redirect(url_for('investor_dashboard'))


# Investor pending investments page
@app.route('/investor/pending_investments')
def investor_pending_investments():
    if 'user_id' not in session or session.get('role') != 'investor':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get real-time count of pending investments
    pending_count = conn.execute('''
        SELECT COUNT(*) as count FROM investment_requests 
        WHERE investor_id = ? AND status = 'pending'
    ''', (session['user_id'],)).fetchone()['count']
    
    pending_requests = conn.execute('''
        SELECT ir.*, i.title, i.summary, i.product_image, u.username as creator_name
        FROM investment_requests ir
        JOIN ideas i ON ir.idea_id = i.id
        JOIN users u ON ir.creator_id = u.id
        WHERE ir.investor_id = ? AND ir.status = 'pending'
        ORDER BY ir.created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    approved_requests = conn.execute('''
        SELECT ir.*, i.title, i.summary, i.product_image, u.username as creator_name
        FROM investment_requests ir
        JOIN ideas i ON ir.idea_id = i.id
        JOIN users u ON ir.creator_id = u.id
        WHERE ir.investor_id = ? AND ir.status = 'approved'
        ORDER BY ir.updated_at DESC
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    
    return render_template('investor_pending_investments.html', 
                         pending_requests=pending_requests,
                         approved_requests=approved_requests,
                         pending_count=pending_count,
                         username=session.get('username'))


#route for investor wallet
@app.route('/investor_wallet')
def investor_wallet():
    if 'user_id' not in session or session.get('role') != 'investor':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute("SELECT wallet_balance FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    wallet_balance = user['wallet_balance'] if user else 0.0

    recent_transactions = conn.execute('''
        SELECT amount, type, created_at
        FROM wallet_transactions
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 5
    ''', (session['user_id'],)).fetchall()
    conn.close()
    
    return render_template('investor_wallet.html', 
                           balance=wallet_balance, 
                           transactions=recent_transactions,
                           username=session.get('username'))


@app.route('/investor/add_funds', methods=['GET', 'POST'])
def investor_add_funds():
    if 'user_id' not in session or session.get('role') != 'investor':
        return redirect(url_for('login'))

    user_id = session['user_id']
    bkash_number_hint = '01825877368' # This is the "correct" number for demo purposes
    otp_code_hint = '456721'       # This is the "correct" OTP for demo purposes
    bkash_pin_hint = '1234'         # This is the "correct" PIN for demo purposes

    # Determine the current step of the payment process
    current_step = request.form.get('current_step', 'number')
    
    # Initialize amount, it will be updated based on form submission
    amount = None

    if request.method == 'POST':
        # Step 1: Handle phone number and amount submission
        if current_step == 'number':
            phone_number = request.form.get('bkash_number')
            amount = request.form.get('amount', type=float) # Get amount from the input field
            
            # Input validation: Check if amount is a positive number
            if amount is None or amount <= 0:
                flash('Please enter a valid amount.', 'danger')
                return render_template('payment_gateway.html', step='number', bkash_number=phone_number, amount=0)
            
            # Transaction limit check: Ensures amount does not exceed 50,000 BDT
            if amount > 50000:
                flash('The maximum limit per transaction is 50,000 BDT.', 'danger')
                return render_template('payment_gateway.html', step='number', bkash_number=phone_number, amount=amount)

            if phone_number == bkash_number_hint:
                session['bkash_number'] = phone_number # Store in session for next step
                session['add_fund_amount'] = amount # Store amount in session
                return render_template('payment_gateway.html', step='otp', bkash_number=phone_number, amount=amount)
            else:
                flash("Invalid Bkash number. Please try again.", "danger")
                return render_template('payment_gateway.html', step='number', bkash_number=phone_number, amount=amount)

        # Step 2: Handle OTP validation
        elif current_step == 'otp':
            otp = request.form.get('otp')
            bkash_number = session.get('bkash_number')
            amount = session.get('add_fund_amount') # Retrieve amount from session

            if otp == otp_code_hint:
                return render_template('payment_gateway.html', step='pin', bkash_number=bkash_number, amount=amount)
            else:
                flash("Incorrect OTP. Please try again.", "danger")
                return render_template('payment_gateway.html', step='otp', bkash_number=bkash_number, amount=amount)

        # Step 3: Handle PIN validation and complete transaction
        elif current_step == 'pin':
            pin = request.form.get('pin')
            bkash_number = session.get('bkash_number') # Not strictly needed here, but for consistency
            amount = session.get('add_fund_amount') # Retrieve amount from session

            if pin == bkash_pin_hint:
                conn = get_db_connection()
                try:
                    # Update user's wallet balance
                    conn.execute("UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?", (amount, user_id))
                    
                    # Log the transaction
                    conn.execute('''
                        INSERT INTO wallet_transactions (user_id, amount, type, status)
                        VALUES (?, ?, ?, ?)
                    ''', (user_id, amount, 'Add Funds', 'Completed'))
                    
                    conn.commit()
                    flash(f"BDT {amount:,.2f} has been added to your wallet successfully!", "success")
                    # Clear session variables after successful transaction
                    session.pop('bkash_number', None)
                    session.pop('add_fund_amount', None)
                    return redirect(url_for('investor_wallet'))
                except sqlite3.Error as e:
                    conn.rollback()
                    flash(f"An error occurred during the transaction: {e}", "danger")
                finally:
                    conn.close()
            else:
                flash("Incorrect PIN. Please try again.", "danger")
                return render_template('payment_gateway.html', step='pin', bkash_number=bkash_number, amount=amount)
    
    # If it's a GET request or initial load, render the first step
    # Make sure amount is passed for initial rendering, possibly 0 or a default
    return render_template('payment_gateway.html', step='number', amount=0)


## ----------------------------------- ADMIN LOGIC STARTS FROM HERE ------------------------------------------------------------##

# main ADMIN dashboard
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    total_users = conn.execute("SELECT COUNT(*) FROM users WHERE role IN ('creator', 'investor')").fetchone()[0]
    total_ideas = conn.execute("SELECT COUNT(*) FROM ideas").fetchone()[0]
    conn.close()

    return render_template('admin_dashboard.html', username=session.get('username'), total_users=total_users,
                           total_ideas=total_ideas)


# user management inside admin_dashboard.html
@app.route('/user_management')
def user_management():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'creator'")
    total_creators = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'investor'")
    total_investors = cursor.fetchone()[0]
    cursor.execute("SELECT id, username, email, role, verified, full_name, phone, gov_id, linkedin_id, present_address FROM users WHERE role IN ('creator', 'investor')")
    all_users = cursor.fetchall()
    conn.close()

    return render_template('user_management.html', username=session.get('username'), total_creators=total_creators,
                           total_investors=total_investors, all_users=all_users)


#admin deletes a user from user_management
@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    # Prevent admin from deleting other admins or themselves
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user_to_delete_role = cursor.fetchone()
    if user_to_delete_role and user_to_delete_role['role'] == 'admin':
        flash("Cannot delete an admin user.", "danger")
        conn.close()
        return redirect(url_for('user_management'))

    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('user_management'))



# verification request from creator is shown in admin panel (verify creator button)
@app.route('/admin/verify_creators')
def verify_creators():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    creators = conn.execute(
        "SELECT id, username, email, full_name, phone, gov_id, linkedin_id, present_address FROM users WHERE role='creator' AND verified=0 AND full_name IS NOT NULL AND full_name != ''"
    ).fetchall()
    conn.close()
    return render_template('admin_verify_creator.html', creators=creators)


# verification request from investor is shown in admin panel (verify investor button)
@app.route('/admin/verify_investors')
def verify_investors():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    investors = conn.execute(
        "SELECT id, username, email, full_name, phone, gov_id, linkedin_id, present_address FROM users WHERE role='investor' AND verified=0 AND full_name IS NOT NULL AND full_name != ''"
    ).fetchall()
    conn.close()
    return render_template('admin_verify_investor.html', investors=investors)


# Admin unverifies a verified user by setting status to 2(declined/unverified)
@app.route('/unverify_user/<int:user_id>/<role>')
def unverify_user(user_id, role):
    # Ensure only admins can perform this action
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Prevent un-verifying an admin
    if role.lower() == 'admin':
        flash("Cannot unverify an admin user.", "danger")
        conn.close()
        return redirect(url_for('user_management'))

    # Update the user's status to 2 (Declined/Unverified)
    cursor.execute("UPDATE users SET verified = 2 WHERE id = ?", (user_id,))
    conn.commit()

    conn.close()
    return redirect(url_for('user_management'))


#admin approves a creator request in admin_verify_creator.html
@app.route('/admin/approve_creator/<int:user_id>')
def approve_creator(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute("UPDATE users SET verified=1 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))


#admin approves an investor request in admin_verify_investor.html
@app.route('/admin/approve_investor/<int:user_id>')
def approve_investor(user_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute("UPDATE users SET verified=1 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))


#admin declines a creator request by setting verified status to 2
@app.route('/decline_creator/<int:user_id>')
def decline_creator(user_id):
    # Ensure only admins can perform this action
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    # Set verified to 2 to indicate a declined status, so it no longer appears as 'pending' (0)
    conn.execute('UPDATE users SET verified = 2 WHERE id = ?, role = "creator"', (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('verify_creators'))


#admin declines an investor request by setting verified status to 2
@app.route('/decline_investor/<int:user_id>')
def decline_investor(user_id):
    # Ensure only admins can perform this action
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    # Set verified to 2 to indicate a declined status, so it no longer appears as 'pending' (0)
    conn.execute('UPDATE users SET verified = 2 WHERE id = ?, role = "investor"', (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('verify_investors'))


#Show ideas info in manage ideas(admin dashboard)
@app.route('/admin_ideas')
def admin_ideas():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    ideas = conn.execute('''
        SELECT 
            i.id, 
            i.title, 
            i.category, 
            i.summary, 
            i.industry,
            i.funding_needed,
            i.equity_offered,
            i.contact_email,
            u.username 
        FROM ideas i 
        JOIN users u ON i.creator_id = u.id
    ''').fetchall()
    conn.close()

    return render_template('admin_ideas.html', ideas=ideas)


# Remove ideas from ideas management(admin dashboard)
@app.route('/remove_idea/<int:idea_id>')
def remove_idea(idea_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute('DELETE FROM ideas WHERE id = ?', (idea_id,))
    conn.commit()
    conn.close()

    # Redirect back to the admin dashboard after deletion
    # The dashboard will then re-fetch the new total_ideas count
    flash('Idea removed successfully.', 'success')
    return redirect(url_for('admin_dashboard'))



##  ----------------------------------- ADMIN LOGIC ENDS ----------------------------------------------------------- ##


# Notifications page
@app.route('/notifications')
def notifications():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    notifications = conn.execute('''
        SELECT * FROM notifications 
        WHERE user_id = ? 
        ORDER BY created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    # Mark all notifications as read
    conn.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ?', (session['user_id'],))
    conn.commit()
    conn.close()
    
    return render_template('notifications.html', 
                         notifications=notifications,
                         username=session.get('username'),
                         role=session.get('role'))


# Get unread notification count (for navbar badge)
@app.route('/api/unread_notifications_count')
def unread_notifications_count():
    if 'user_id' not in session:
        return {'count': 0}
    
    conn = get_db_connection()
    count = conn.execute('''
        SELECT COUNT(*) as count FROM notifications 
        WHERE user_id = ? AND is_read = 0
    ''', (session['user_id'],)).fetchone()['count']
    conn.close()
    
    return {'count': count}


@app.route("/privacy-policy")
def privacy_policy():
    return render_template("privacy_policy.html")

@app.route("/terms-of-service")
def terms_of_service():
    return render_template("terms_of_service.html")

@app.route("/about_us")
def about_us():
    return render_template("about_us.html")


@app.route("/contact-us")
def contact_us():
    return render_template("contact_us.html")


# Investment details page
@app.route('/investment_details/<int:request_id>')
def investment_details(request_id):
    if 'user_id' not in session or session.get('role') != 'investor':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get investment request details with idea information
    request_details = conn.execute('''
        SELECT ir.*, i.title, i.summary, i.product_image, i.funding_needed, 
               i.equity_offered, i.description, u.username as creator_name
        FROM investment_requests ir
        JOIN ideas i ON ir.idea_id = i.id
        JOIN users u ON ir.creator_id = u.id
        WHERE ir.id = ? AND ir.investor_id = ? AND ir.status = 'approved'
    ''', (request_id, session['user_id'])).fetchone()
    
    conn.close()
    
    if not request_details:
        flash('Investment details not found or not accessible.', 'danger')
        return redirect(url_for('investor_pending_investments'))
    
    return render_template('investment_details.html', 
                         idea=request_details,
                         investment_amount=request_details['investment_amount'])


# Profile page
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get user information
    user = conn.execute('''
        SELECT * FROM users WHERE id = ?
    ''', (session['user_id'],)).fetchone()
    
    # Get user statistics based on role
    if user['role'] == 'creator':
        stats = conn.execute('''
            SELECT 
                COUNT(i.id) as total_ideas,
                COUNT(ir.id) as total_investments,
                COALESCE(SUM(CASE WHEN ir.status = 'approved' THEN ir.investment_amount ELSE 0 END), 0) as total_funding
            FROM users u
            LEFT JOIN ideas i ON u.id = i.creator_id
            LEFT JOIN investment_requests ir ON i.id = ir.idea_id
            WHERE u.id = ?
        ''', (session['user_id'],)).fetchone()
    else:  # investor
        stats = conn.execute('''
            SELECT 
                COUNT(CASE WHEN ir.status = 'approved' THEN 1 END) as active_investments,
                COALESCE(SUM(ir.investment_amount), 0) as total_invested,
                CASE 
                    WHEN COUNT(ir.id) > 0 THEN 
                        ROUND((COUNT(CASE WHEN ir.status = 'approved' THEN 1 END) * 100.0 / COUNT(ir.id)), 1)
                    ELSE 0 
                END as success_rate
            FROM investment_requests ir
            WHERE ir.investor_id = ?
        ''', (session['user_id'],)).fetchone()
    
    conn.close()
    
    return render_template('profile.html', user=user, stats=stats)


# Creator portfolio page
@app.route('/creator/portfolio')
def creator_portfolio():
    if 'user_id' not in session or session.get('role') != 'creator':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get creator's ideas with additional portfolio data
    ideas = conn.execute('''
        SELECT 
            i.*,
            COALESCE(SUM(CASE WHEN ir.status = 'approved' THEN ir.investment_amount ELSE 0 END), 0) as funded_amount,
            COUNT(ir.id) as total_requests,
            'active' as status
        FROM ideas i
        LEFT JOIN investment_requests ir ON i.id = ir.idea_id
        WHERE i.creator_id = ?
        GROUP BY i.id
        ORDER BY i.created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    # Get portfolio statistics
    portfolio_stats = conn.execute('''
        SELECT 
            COUNT(i.id) as total_ideas,
            COALESCE(SUM(i.funding_needed), 0) as total_funding_goal,
            COUNT(ir.id) as investment_requests,
            COALESCE(SUM(CASE WHEN ir.status = 'approved' THEN ir.investment_amount ELSE 0 END), 0) as total_funding,
            0 as total_views
        FROM ideas i
        LEFT JOIN investment_requests ir ON i.id = ir.idea_id
        WHERE i.creator_id = ?
    ''', (session['user_id'],)).fetchone()
    
    conn.close()
    
    return render_template('creator_portfolio.html', 
                         ideas=ideas,
                         portfolio_stats=portfolio_stats,
                         username=session.get('username'),
                         verified=session.get('verified'))


# logout logic
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))



# Runs the app from here
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
