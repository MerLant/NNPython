from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Замените на ваш секретный ключ
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Рекомендуется отключить для производительности
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Модель пользователя
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Модель заявления
class Statement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    car_number = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Новое')

    user = db.relationship('User', backref=db.backref('statements', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Формы
class RegistrationForm(FlaskForm):
    fullname = StringField('ФИО', validators=[DataRequired(), Length(min=2, max=150)])
    phone = StringField('Телефон', validators=[DataRequired(), Length(min=5, max=20)])
    email = StringField('Электронная почта', validators=[DataRequired(), Email()])
    username = StringField('Логин', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Подтвердите пароль', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Зарегистрироваться')

class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

class StatementForm(FlaskForm):
    car_number = StringField('Номер автомобиля', validators=[DataRequired(), Length(min=2, max=20)])
    description = TextAreaField('Описание нарушения', validators=[DataRequired(), Length(min=10)])
    submit = SubmitField('Отправить заявление')

# Админ-панель
class AdminModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.username == 'admin'

    def inaccessible_callback(self, name, **kwargs):
        flash('Доступ запрещён. Пожалуйста, войдите как администратор.', 'danger')
        return redirect(url_for('login'))

admin = Admin(app, name='Админ-панель', template_mode='bootstrap3')
admin.add_view(AdminModelView(User, db.session))
admin.add_view(AdminModelView(Statement, db.session))

# Маршруты
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('statements'))
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter(
            (User.username == form.username.data) | (User.email == form.email.data)
        ).first()
        if existing_user:
            flash('Пользователь с таким логином или электронной почтой уже существует.', 'danger')
            return render_template('register.html', form=form)
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(
            fullname=form.fullname.data,
            phone=form.phone.data,
            email=form.email.data,
            username=form.username.data,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Вы успешно зарегистрированы! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('statements'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Вы успешно вошли в систему.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('statements'))
        else:
            flash('Неверный логин или пароль.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы успешно вышли из системы.', 'success')
    return redirect(url_for('login'))

@app.route('/statements')
@login_required
def statements():
    if current_user.username == "admin":
        user_statements = Statement.query.all()
    else:
        user_statements = Statement.query.filter_by(user_id=current_user.id).all()

    return render_template('statements.html', statements=user_statements)

@app.route('/create_statement', methods=['GET', 'POST'])
@login_required
def create_statement():
    form = StatementForm()
    if form.validate_on_submit():
        new_statement = Statement(
            user_id=current_user.id,
            car_number=form.car_number.data,
            description=form.description.data
        )
        db.session.add(new_statement)
        db.session.commit()
        flash('Заявление успешно отправлено.', 'success')
        return redirect(url_for('statements'))
    return render_template('create_statement.html', form=form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Создаём администратора, если он не существует
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                fullname='Администратор',
                phone='0000000000',
                email='admin@example.com',
                username='admin',
                password=generate_password_hash('password', method='pbkdf2:sha256')
            )
            db.session.add(admin_user)
            db.session.commit()
            print('Администратор создан с логином "admin" и паролем "password".')
        else:
            print('Администратор уже существует.')
    app.run(debug=True)
