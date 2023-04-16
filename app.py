from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, DecimalField, SelectField, DateTimeField, TextAreaField, SubmitField, ValidationError, IntegerField
from wtforms.validators import DataRequired
from datetime import datetime, timedelta
from flask_wtf.csrf import generate_csrf

class SummaryFilterForm(FlaskForm):
    filter_by = SelectField('Filter By', choices=[('both', 'Sales and Expenses'), ('sale', 'Sales'), ('expense', 'Expenses')], default='both')
    date_range = SelectField('Date Range', choices=[('month', 'Month'), ('year', 'Year')], default='month')

class SalesForm(FlaskForm):
    date_time = DateTimeField('Date and Time', format='%Y-%m-%d %H:%M:%S', default=datetime.utcnow, validators=[DataRequired()])
    amount = IntegerField('Amount', validators=[DataRequired()])
    currency = SelectField('Currency', choices=[('UYU', 'UYU'), ('USD', 'USD')], default='UYU')
    comment = TextAreaField('Comment')
    submit = SubmitField('Submit Sale', name='submit_sale')

class ExpensesForm(FlaskForm):
    date_time = DateTimeField('Date and Time', format='%Y-%m-%d %H:%M:%S', default=datetime.utcnow, validators=[DataRequired()])
    amount = IntegerField('Amount', validators=[DataRequired()])
    currency = SelectField('Currency', choices=[('UYU', 'UYU'), ('USD', 'USD')], default='UYU')
    comment = TextAreaField('Comment')
    submit = SubmitField('Submit Expense', name='submit_expense')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///farm_management.db'
app.config['SECRET_KEY'] = 'diablo666'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(3), nullable=False)
    comment = db.Column(db.String(200))
    transaction_type = db.Column(db.String(10), nullable=False)
    user = db.relationship("User", back_populates="transactions")

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    transactions = db.relationship('Transaction', back_populates='user', cascade='all, delete-orphan', lazy='dynamic')

@app.route('/summary', methods=['GET', 'POST'])
@login_required
def summary():
    filter_form = SummaryFilterForm()

    filter_by = 'both'
    date_range = 'month'
    if filter_form.validate_on_submit():
        filter_by = filter_form.filter_by.data
        date_range = filter_form.date_range.data

    if date_range == 'month':
        start_date = datetime.utcnow().replace(day=1)
    elif date_range == 'year':
        start_date = datetime.utcnow().replace(month=1, day=1)
    end_date = datetime.utcnow()

    if filter_by == 'both':
        records = Transaction.query.filter_by(user_id=current_user.id).filter(Transaction.date_time.between(start_date, end_date)).order_by(Transaction.date_time.desc()).all()
    else:
        records = Transaction.query.filter_by(user_id=current_user.id, transaction_type=filter_by).filter(Transaction.date_time.between(start_date, end_date)).order_by(Transaction.date_time.desc()).all()

    return render_template('summary.html', filter_form=filter_form, records=records)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register_section', methods=['GET'])
@login_required
def register_section():
    sales_form = SalesForm()
    expenses_form = ExpensesForm()

    sales = Transaction.query.filter_by(user_id=current_user.id, transaction_type='sale').order_by(Transaction.date_time.desc()).limit(5).all()
    expenses = Transaction.query.filter_by(user_id=current_user.id, transaction_type='expense').order_by(Transaction.date_time.desc()).limit(5).all()

    return render_template('register_section.html', sales_form=sales_form, expenses_form=expenses_form, sales=sales, expenses=expenses)

@app.route('/register_sale', methods=['POST'])
@login_required
def register_sale():
    sales_form = SalesForm()
    if sales_form.validate_on_submit():
        sale = Transaction(user_id=current_user.id, transaction_type='sale', date_time=sales_form.date_time.data, amount=sales_form.amount.data, currency=sales_form.currency.data, comment=sales_form.comment.data)
        db.session.add(sale)
        db.session.commit()
        flash('Sale added successfully')
    return redirect(url_for('register_section'))

@app.route('/register_expense', methods=['POST'])
@login_required
def register_expense():
    expenses_form = ExpensesForm()
    if expenses_form.validate_on_submit():
        expense = Transaction(user_id=current_user.id, transaction_type='expense', date_time=expenses_form.date_time.data, amount=expenses_form.amount.data, currency=expenses_form.currency.data, comment=expenses_form.comment.data)
        db.session.add(expense)
        db.session.commit()
        flash('Expense added successfully')
    return redirect(url_for('register_section'))

@app.route('/edit_expense/<int:transaction_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(transaction_id):
    expense = Transaction.query.get_or_404(transaction_id)
    if expense.user_id != current_user.id:
        abort(403)

    form = ExpensesForm(obj=expense)
    if form.validate_on_submit():
        expense.date_time = form.date_time.data
        expense.amount = form.amount.data
        expense.currency = form.currency.data
        expense.comment = form.comment.data
        db.session.commit()
        flash('Expense updated successfully')

        next_page = request.args.get('next', 'summary')
        filter_by = request.args.get('filter_by', 'both')
        date_range = request.args.get('date_range', 'month')
        return redirect(url_for(next_page, filter_by=filter_by, date_range=date_range))

    return render_template('edit_expense.html', form=form)



@app.route('/delete_expense/<int:transaction_id>', methods=['POST'])
@login_required
def delete_expense(transaction_id):
    csrf_token = generate_csrf()
    if request.form.get('csrf_token') != csrf_token:
        abort(400)

    db.session.delete(expense)
    db.session.commit()
    flash('Expense deleted successfully')

    filter_by = request.args.get('filter_by')
    date_range = request.args.get('date_range')
    return redirect(url_for('summary', filter_by=filter_by, date_range=date_range))


@app.route('/edit_sale/<int:transaction_id>', methods=['GET', 'POST'])
@login_required
def edit_sale(transaction_id):
    sale = Transaction.query.get_or_404(transaction_id)
    if sale.user_id != current_user.id:
        abort(403)

    form = SalesForm(obj=sale)
    if form.validate_on_submit():
        sale.date_time = form.date_time.data
        sale.amount = form.amount.data
        sale.currency = form.currency.data
        sale.comment = form.comment.data
        db.session.commit()
        flash('Sale updated successfully')
        
        next_page = request.args.get('next', 'summary')
        filter_by = request.args.get('filter_by', 'both')
        date_range = request.args.get('date_range', 'month')
        return redirect(url_for(next_page, filter_by=filter_by, date_range=date_range))

    return render_template('edit_sale.html', form=form)

@app.route('/delete_sale/<int:transaction_id>', methods=['POST'])
@login_required
def delete_sale(transaction_id):
    csrf_token = generate_csrf()
    if request.form.get('csrf_token') != csrf_token:
        abort(400)

    db.session.delete(sale)
    db.session.commit()
    flash('Sale deleted successfully')
    filter_by = request.args.get('filter_by')
    date_range = request.args.get('date_range')
    return redirect(url_for('summary', filter_by=filter_by, date_range=date_range))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))

        flash('Invalid username or password. Please try again.')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
    return render_template('index.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
