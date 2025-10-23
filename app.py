from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_scss import Scss
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = os.environ.get("PAWRADISE_SECRET", "pawradise_secret")

Scss(app, static_dir='static', asset_dir='assets/scss')

basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "pawradise.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
UPLOAD_FOLDER = os.path.join(basedir, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXT = {"png", "jpg", "jpeg", "gif"}

db = SQLAlchemy(app)

ADMIN_USERNAME = "admin"
ADMIN_EMAIL = "admin@pawradise.com"
ADMIN_PASSWORD = "admin123"

# ADDED: Make timedelta available in all templates
@app.context_processor
def utility_processor():
    return dict(timedelta=timedelta, now=datetime.utcnow)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please login to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in roles:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('home'))
            return f(*args, **kwargs)

        return decorated_function

    return decorator


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    def is_admin(self):
        return self.role == "admin"

    def is_seller(self):
        return self.role == "seller"

    def is_owner(self):
        return self.role == "owner"


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    image = db.Column(db.String(255))
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    stock = db.Column(db.Integer, default=0)
    sales_count = db.Column(db.Integer, default=0)
    category = db.Column(db.String(50), nullable=True)


class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer, default=1)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=True)
    product_name = db.Column(db.String(100))
    quantity = db.Column(db.Integer)
    unit_price = db.Column(db.Float)
    total_price = db.Column(db.Float)
    customer_name = db.Column(db.String(100))
    address = db.Column(db.Text)
    contact_number = db.Column(db.String(20))
    payment_method = db.Column(db.String(50))
    date_of_purchase = db.Column(db.DateTime, default=datetime.utcnow)
    estimated_delivery = db.Column(db.DateTime)
    status = db.Column(db.String(50), default="Pending")


class Gallery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    alt_text = db.Column(db.String(255))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)


class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def create_admin_user():
    """Create default admin user if it doesn't exist"""
    admin = User.query.filter_by(username=ADMIN_USERNAME).first()
    if not admin:
        hashed_pw = generate_password_hash(ADMIN_PASSWORD)
        admin = User(
            username=ADMIN_USERNAME,
            email=ADMIN_EMAIL,
            password=hashed_pw,
            role="admin"
        )
        db.session.add(admin)
        db.session.commit()
        print(f"✓ Admin user created: {ADMIN_USERNAME}")
    else:
        print(f"✓ Admin user already exists: {ADMIN_USERNAME}")


@app.route('/')
def home():
    best_sellers = Product.query.order_by(Product.sales_count.desc()).limit(6).all()
    return render_template('home.html', best_sellers=best_sellers)


@app.route('/shop')
def shop():
    category = request.args.get('category')
    if category:
        products = Product.query.filter_by(category=category).all()
    else:
        products = Product.query.all()
    return render_template('shop.html', products=products)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        message = request.form.get('message', '').strip()

        if name and email and message:
            new_message = ContactMessage(name=name, email=email, message=message)
            db.session.add(new_message)
            db.session.commit()
            flash('Thank you for contacting us! We will get back to you soon.', 'success')
            return redirect(url_for('contact'))
        else:
            flash('Please fill in all fields.', 'error')

    return render_template('contact.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        if role == 'admin':
            flash('Admin accounts cannot be registered through the form. Contact the owner.', 'error')
            return redirect(url_for('register'))

        if role not in ['seller', 'customer']:
            flash('Invalid role selected.', 'error')
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password)

        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            flash('Username or email already exists.', 'error')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email, password=hashed_pw, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['username'] = user.username
            session['role'] = user.role
            session['user_id'] = user.id
            flash('Login successful!', 'success')

            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role in ['seller', 'owner']:
                return redirect(url_for('seller_dashboard'))
            else:
                return redirect(url_for('customer_dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))


@app.route('/admin')
@login_required
@role_required('admin')
def admin_dashboard():
    products = Product.query.all()
    all_orders = Order.query.order_by(Order.date_of_purchase.desc()).all()
    all_users = User.query.all()
    total_sales = db.session.query(db.func.sum(Order.total_price)).scalar() or 0
    total_orders = Order.query.count()

    return render_template('admin_dashboard.html',
                           products=products,
                           all_orders=all_orders,
                           all_users=all_users,
                           total_sales=total_sales,
                           total_orders=total_orders)


@app.route('/admin/update/<int:id>', methods=['POST'])
@login_required
@role_required('admin')
def update_product(id):
    product = Product.query.get(id)
    if not product:
        flash('Product not found.', 'error')
        return redirect(url_for('admin_dashboard'))

    product.name = request.form.get('name', product.name)
    try:
        product.price = float(request.form.get('price', product.price))
        product.stock = int(request.form.get('stock', product.stock))
    except ValueError:
        pass
    product.description = request.form.get('description', product.description)
    db.session.commit()
    flash('Product updated.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete/<int:id>')
@login_required
@role_required('admin')
def delete_product(id):
    product = Product.query.get(id)
    if product:
        db.session.delete(product)
        db.session.commit()
        flash('Product deleted.', 'success')
    else:
        flash('Product not found.', 'error')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/update_order_status/<int:id>', methods=['POST'])
@login_required
@role_required('admin')
def update_order_status(id):
    order = Order.query.get(id)
    if order:
        new_status = request.form.get('status', order.status)
        order.status = new_status
        db.session.commit()
        flash(f'Order #{id} status updated to {new_status}.', 'success')
    else:
        flash('Order not found.', 'error')

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete_user/<int:id>')
@login_required
@role_required('admin')
def delete_user(id):
    user = User.query.get(id)
    if user:
        if user.role in ['admin', 'owner']:
            flash('Cannot delete admin or owner accounts.', 'error')
        else:
            db.session.delete(user)
            db.session.commit()
            flash(f'User {user.username} deleted successfully.', 'success')
    else:
        flash('User not found.', 'error')

    return redirect(url_for('admin_dashboard'))


@app.route('/seller')
@login_required
@role_required('seller', 'owner')
def seller_dashboard():
    products = Product.query.filter_by(seller_id=session['user_id']).all()
    return render_template('seller_dashboard.html', products=products)


@app.route('/add_product', methods=['POST'])
@login_required
@role_required('admin', 'seller', 'owner')
def add_product():
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    price_raw = request.form.get('price', '').strip()
    stock_raw = request.form.get('stock', '0').strip()
    category = request.form.get('category', '').strip()
    image_file = request.files.get('image')

    if not name or not description or not price_raw or not image_file:
        flash("All fields are required.", "error")
        return redirect(request.referrer or url_for('shop'))

    try:
        price = float(price_raw)
        stock = int(stock_raw)
    except ValueError:
        flash("Price and stock must be valid numbers.", "error")
        return redirect(request.referrer or url_for('shop'))

    if image_file and allowed_file(image_file.filename):
        filename = secure_filename(image_file.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image_file.save(image_path)
        image_path_db = f"uploads/{filename}"
    else:
        flash("Invalid image format.", "error")
        return redirect(request.referrer or url_for('shop'))

    seller_id = session['user_id'] if session.get('role') in ['seller', 'owner'] else None
    new_product = Product(
        name=name,
        description=description,
        price=price,
        image=image_path_db,
        seller_id=seller_id,
        stock=stock,
        category=category
    )
    db.session.add(new_product)
    db.session.commit()

    flash("Product added successfully!", "success")
    return redirect(request.referrer or url_for('shop'))


@app.route('/seller/update/<int:id>', methods=['POST'])
@login_required
@role_required('seller', 'owner')
def seller_update_product(id):
    product = Product.query.get(id)
    if not product or product.seller_id != session['user_id']:
        flash('Product not found or access denied.', 'error')
        return redirect(url_for('seller_dashboard'))

    product.name = request.form.get('name', product.name)
    try:
        product.price = float(request.form.get('price', product.price))
        product.stock = int(request.form.get('stock', product.stock))
    except ValueError:
        pass
    product.description = request.form.get('description', product.description)
    db.session.commit()
    flash('Product updated.', 'success')
    return redirect(url_for('seller_dashboard'))


@app.route('/seller/delete/<int:id>')
@login_required
@role_required('seller', 'owner')
def seller_delete_product(id):
    product = Product.query.get(id)
    if product and product.seller_id == session['user_id']:
        db.session.delete(product)
        db.session.commit()
        flash('Product deleted.', 'success')
    else:
        flash('Product not found or access denied.', 'error')
    return redirect(url_for('seller_dashboard'))


@app.route('/customer')
@login_required
@role_required('customer')
def customer_dashboard():
    orders = Order.query.filter_by(user_id=session['user_id']).order_by(Order.date_of_purchase.desc()).all()
    return render_template('customer_dashboard.html', orders=orders)


@app.route('/customer/cancel_order/<int:id>')
@login_required
@role_required('customer')
def customer_cancel_order(id):
    order = Order.query.get(id)
    if order and order.user_id == session['user_id']:
        if order.status in ['Pending', 'Confirmed']:
            order.status = 'Cancelled'

            product = Product.query.get(order.product_id)
            if product:
                product.stock += order.quantity
                product.sales_count -= order.quantity

            db.session.commit()
            flash('Order cancelled successfully.', 'success')
        else:
            flash('This order cannot be cancelled.', 'error')
    else:
        flash('Order not found or access denied.', 'error')

    return redirect(url_for('customer_dashboard'))


@app.route('/cart')
@login_required
def cart():
    if session.get('role') == 'admin':
        flash('Admin accounts cannot use the shopping cart.', 'error')
        return redirect(url_for('shop'))

    cart_items = db.session.query(Cart, Product).join(
        Product, Cart.product_id == Product.id
    ).filter(Cart.user_id == session['user_id']).all()

    return render_template('cart.html', cart_items=cart_items)


@app.route('/add_to_cart/<int:product_id>', methods=['GET', 'POST'])
@login_required
def add_to_cart(product_id):
    if session.get('role') == 'admin':
        flash('Admin accounts cannot purchase products.', 'error')
        return redirect(url_for('shop'))

    product = Product.query.get(product_id)
    if not product or product.stock < 1:
        flash('Product is out of stock.', 'error')
        return redirect(url_for('shop'))

    quantity = 1
    if request.method == 'POST':
        try:
            quantity = int(request.form.get('quantity', 1))
        except ValueError:
            quantity = 1

    cart_item = Cart.query.filter_by(
        user_id=session['user_id'],
        product_id=product_id
    ).first()

    if cart_item:
        if product.stock >= cart_item.quantity + quantity:
            cart_item.quantity += quantity
        else:
            flash('Not enough stock available.', 'error')
            return redirect(url_for('shop'))
    else:
        if product.stock >= quantity:
            new_item = Cart(user_id=session['user_id'], product_id=product_id, quantity=quantity)
            db.session.add(new_item)
        else:
            flash('Not enough stock available.', 'error')
            return redirect(url_for('shop'))

    db.session.commit()
    flash('Added to cart.', 'success')
    return redirect(url_for('shop'))


@app.route('/cart/remove/<int:cart_id>')
@login_required
def remove_from_cart(cart_id):
    cart_item = Cart.query.get(cart_id)
    if cart_item and cart_item.user_id == session['user_id']:
        db.session.delete(cart_item)
        db.session.commit()
        flash('Item removed from cart.', 'success')

    return redirect(url_for('cart'))


@app.route('/checkout')
@login_required
def checkout():
    if session.get('role') == 'admin':
        flash('Admin accounts cannot purchase products.', 'error')
        return redirect(url_for('shop'))

    cart_items = db.session.query(Cart, Product).join(
        Product, Cart.product_id == Product.id
    ).filter(Cart.user_id == session['user_id']).all()

    if not cart_items:
        flash('Your cart is empty.', 'error')
        return redirect(url_for('cart'))

    return render_template('order_form.html', cart_items=cart_items, buy_now=False)


@app.route('/buy_now/<int:product_id>')
@login_required
def buy_now(product_id):
    if session.get('role') == 'admin':
        flash('Admin accounts cannot purchase products.', 'error')
        return redirect(url_for('shop'))

    product = Product.query.get(product_id)
    if not product or product.stock < 1:
        flash('Product is out of stock.', 'error')
        return redirect(url_for('shop'))

    session['buy_now_product'] = product_id
    return render_template('order_form.html', cart_items=[(None, product)], buy_now=True)


@app.route('/place_order', methods=['POST'])
@login_required
def place_order():
    customer_name = request.form.get('customer_name', '').strip()
    address = request.form.get('address', '').strip()
    contact_number = request.form.get('contact_number', '').strip()
    payment_method = request.form.get('payment_method', '').strip()

    if not all([customer_name, address, contact_number, payment_method]):
        flash('Please fill in all fields.', 'error')
        return redirect(url_for('checkout'))

    buy_now = request.form.get('buy_now') == 'true'

    if buy_now:
        product_id = session.pop('buy_now_product', None)
        if not product_id:
            flash('Product not found.', 'error')
            return redirect(url_for('shop'))

        product = Product.query.get(product_id)
        if not product or product.stock < 1:
            flash('Product is out of stock.', 'error')
            return redirect(url_for('shop'))

        items = [(None, product)]
        quantity = 1
    else:
        items = db.session.query(Cart, Product).join(
            Product, Cart.product_id == Product.id
        ).filter(Cart.user_id == session['user_id']).all()

        if not items:
            flash('Your cart is empty.', 'error')
            return redirect(url_for('cart'))

    for item, product in items:
        qty = item.quantity if item else 1

        if product.stock < qty:
            flash(f'Not enough stock for {product.name}.', 'error')
            return redirect(url_for('checkout' if not buy_now else 'shop'))

        total = product.price * qty
        purchase_date = datetime.utcnow()
        estimated_delivery = purchase_date + timedelta(days=7)

        new_order = Order(
            user_id=session['user_id'],
            product_id=product.id,
            product_name=product.name,
            quantity=qty,
            unit_price=product.price,
            total_price=total,
            customer_name=customer_name,
            address=address,
            contact_number=contact_number,
            payment_method=payment_method,
            date_of_purchase=purchase_date,
            estimated_delivery=estimated_delivery,
            status="Pending"
        )
        db.session.add(new_order)

        product.stock -= qty
        product.sales_count += qty

        if item:
            db.session.delete(item)

    db.session.commit()
    flash('Order placed successfully! Your estimated delivery is in 7 days.', 'success')
    return redirect(url_for('orders'))


@app.route('/orders')
@login_required
def orders():
    orders_list = Order.query.filter_by(user_id=session['user_id']).order_by(Order.date_of_purchase.desc()).all()
    return render_template('orders.html', orders=orders_list)


@app.route('/track_order', methods=['GET', 'POST'])
@login_required
def track_order():
    if session.get('role') == 'admin':
        flash('Admin accounts cannot track orders.', 'error')
        return redirect(url_for('admin_dashboard'))

    order = None
    if request.method == 'POST':
        search_id = request.form.get('order_id')
        if search_id and search_id.isdigit():
            order = Order.query.filter_by(id=int(search_id), user_id=session['user_id']).first()
            if not order:
                flash('Order not found or access denied.', 'error')
        else:
            flash('Please enter a valid order ID.', 'error')

    order_id = request.args.get('order_id')
    if order_id and order_id.isdigit():
        order = Order.query.filter_by(id=int(order_id), user_id=session['user_id']).first()

    return render_template('track_order.html', order=order)


@app.route('/gallery')
def gallery():
    photos = Gallery.query.order_by(Gallery.uploaded_at.desc()).all()
    return render_template('gallery.html', photos=photos)


@app.route('/upload_photo', methods=['POST'])
@login_required
def upload_photo():
    if 'photo' not in request.files:
        flash('No photo selected.', 'error')
        return redirect(url_for('gallery'))

    file = request.files['photo']
    if file.filename == '':
        flash('No selected file.', 'error')
        return redirect(url_for('gallery'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        new_photo = Gallery(filename=filename, alt_text=f"{session['username']}'s photo")
        db.session.add(new_photo)
        db.session.commit()

        flash('Photo uploaded successfully!', 'success')
        return redirect(url_for('gallery'))
    else:
        flash('File type not allowed.', 'error')
        return redirect(url_for('gallery'))


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()
    app.run(debug=True)