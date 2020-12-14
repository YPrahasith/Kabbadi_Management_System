
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, FormField
from wtforms.validators import InputRequired,Email, Length, DataRequired
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(25))

class Auto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    field1 = db.Column(db.String(120), unique=False, nullable=False)
    field2 = db.Column(db.String(120), unique=False, nullable=False)
    field3 = db.Column(db.String(120), unique=False, nullable=False)

    def __repr__(self):
        return '<Field1 %r>' % self.field1

class Car(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    field1 = db.Column(db.String(120), unique=False, nullable=False)
    field2 = db.Column(db.String(120), unique=False, nullable=False)
    field3 = db.Column(db.String(120), unique=False, nullable=False)
    field4 = db.Column(db.String(120), unique=False, nullable=False)

    def __repr__(self):
        return '<Field1 %r>' % self.field1

class Spa(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    field1 = db.Column(db.String(120), unique=False, nullable=False)
    field2 = db.Column(db.String(120), unique=False, nullable=False)
    field3 = db.Column(db.String(120), unique=False, nullable=False)

    def __repr__(self):
        return '<Field1 %r>' % self.field1

class Cloth(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    field1 = db.Column(db.String(120), unique=False, nullable=False)
    field2 = db.Column(db.String(120), unique=False, nullable=False)
    field3 = db.Column(db.String(120), unique=False, nullable=False)
    field4 = db.Column(db.String(120), unique=False, nullable=False)
    field5 = db.Column(db.String(120), unique=False, nullable=False)

    def __repr__(self):
        return '<Field1 %r>' % self.field1

class Saloon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    field1 = db.Column(db.String(120), unique=False, nullable=False)
    field2 = db.Column(db.String(120), unique=False, nullable=False)
    field3 = db.Column(db.String(120), unique=False, nullable=False)
    field4 = db.Column(db.String(120), unique=False, nullable=False)
    field5 = db.Column(db.String(120), unique=False, nullable=False)

    def __repr__(self):
        return '<Field1 %r>' % self.field1

class House(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    field1 = db.Column(db.String(120), unique=False, nullable=False)
    field2 = db.Column(db.String(120), unique=False, nullable=False)
    field3 = db.Column(db.String(120), unique=False, nullable=False)

    def __repr__(self):
        return '<Field1 %r>' % self.field1

class Luxury(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    field1 = db.Column(db.String(120), unique=False, nullable=False)
    field2 = db.Column(db.String(120), unique=False, nullable=False)
    field3 = db.Column(db.String(120), unique=False, nullable=False)
    field4 = db.Column(db.String(120), unique=False, nullable=False)
    field5 = db.Column(db.String(120), unique=False, nullable=False)
    field6 = db.Column(db.String(120), unique=False, nullable=False)

    def __repr__(self):
        return '<Field1 %r>' % self.field1

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=25)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=25)])
    email = StringField('email', validators=[InputRequired(),Email(message='Invalid email'), Length(max=50)])

class AutoForm(FlaskForm):
    field1 = StringField(label="Points", validators=[DataRequired()])
    field2 = StringField(label="Appearance id", validators=[DataRequired()])
    field3 = StringField(label="Time", validators=[DataRequired()])

class CarForm(FlaskForm):
    field1 = StringField(label="Player id", validators=[DataRequired()])
    field2 = StringField(label="Player Name", validators=[DataRequired()])
    field3 = StringField(label="Nationality", validators=[DataRequired()])
    field4 = StringField(label="Club id", validators=[DataRequired()])

class SpaForm(FlaskForm):
    field1 = StringField(label="League id", validators=[DataRequired()])
    field2 = StringField(label="League Name", validators=[DataRequired()])
    field3 = StringField(label="Country", validators=[DataRequired()])

class SaloonForm(FlaskForm):
    field1 = StringField(label="Club id", validators=[DataRequired()])
    field2 = StringField(label="League id", validators=[DataRequired()])
    field3 = StringField(label="Club Name", validators=[DataRequired()])
    field4 = StringField(label="City", validators=[DataRequired()])
    field5 = StringField(label="Stadium", validators=[DataRequired()])

class ClothForm(FlaskForm):
    field1 = StringField(label="Player id", validators=[DataRequired()])
    field2 = StringField(label="Date", validators=[DataRequired()])
    field3 = StringField(label="Club From ID", validators=[DataRequired()])
    field4 = StringField(label="Club To ID", validators=[DataRequired()])
    field5 = StringField(label="Fees", validators=[DataRequired()])

class HouseForm(FlaskForm):
    field1 = StringField(label="Appearance id", validators=[DataRequired()])
    field2 = StringField(label="Player id", validators=[DataRequired()])
    field3 = StringField(label="Match id", validators=[DataRequired()])

class LuxuryForm(FlaskForm):
    field1 = StringField(label="Match id", validators=[DataRequired()])
    field2 = StringField(label="Club Home id", validators=[DataRequired()])
    field3 = StringField(label="Club Away id", validators=[DataRequired()])
    field4 = StringField(label="Date", validators=[DataRequired()])
    field5 = StringField(label="Points Home", validators=[DataRequired()])
    field6 = StringField(label="Points Away", validators=[DataRequired()])

class GiantForm(FlaskForm):
    auto = FormField(AutoForm)
    car = FormField(CarForm)
    spa = FormField(SpaForm)
    cloth = FormField(ClothForm)
    house = FormField(HouseForm)
    saloon = FormField(SaloonForm)
    luxury = FormField(LuxuryForm)

@app.route('/', methods=['GET', 'POST'])
def index():
    form = GiantForm()

    if "submit_auto" in request.form and form.auto.validate(form):
        auto = Auto(field1=form.auto.field1.data,
                    field2=form.auto.field2.data,
                    field3=form.auto.field3.data,)
        db.session.add(auto)
        db.session.commit()
        flash('Your details have been submitted', 'auto')
        return redirect(url_for('index'))
    elif "submit_car" in request.form and form.car.validate(form):
        car = Car(field1=form.car.field1.data,
                    field2=form.car.field2.data,
                    field3=form.car.field3.data,
                    field4=form.car.field4.data,)
        db.session.add(car)
        db.session.commit()
        flash('Your details have been submitted', 'car')
        return redirect(url_for('index'))
    elif "submit_spa" in request.form and form.spa.validate(form):
        spa = Spa(field1=form.spa.field1.data,
                    field2=form.spa.field2.data,
                    field3=form.spa.field3.data,)
        db.session.add(spa)
        db.session.commit()
        flash('Your details have been submitted', 'spa')
        return redirect(url_for('index'))
    elif "submit_saloon" in request.form and form.saloon.validate(form):
        saloon = Saloon(field1=form.saloon.field1.data,
                    field2=form.saloon.field2.data,
                    field3=form.saloon.field3.data,
                    field4=form.saloon.field4.data,
                    field5=form.saloon.field5.data,)
        db.session.add(saloon)
        db.session.commit()
        flash('Your details have been submitted', 'saloon')
        return redirect(url_for('index'))
    elif "submit_cloth" in request.form and form.cloth.validate(form):
        cloth = Cloth(field1=form.cloth.field1.data,
                    field2=form.cloth.field2.data,
                    field3=form.cloth.field3.data,
                    field4=form.cloth.field4.data,
                    field5=form.cloth.field5.data,)
        db.session.add(cloth)
        db.session.commit()
        flash('Your details have been submitted', 'cloth')
        return redirect(url_for('index'))
    elif "submit_house" in request.form and form.house.validate(form):
        house = House(field1=form.house.field1.data,
                    field2=form.house.field2.data,
                    field3=form.house.field3.data,)
        db.session.add(house)
        db.session.commit()
        flash('Your details have been submitted', 'house')
        return redirect(url_for('index'))
    elif "submit_luxury" in request.form and form.luxury.validate(form):
        luxury = Luxury(field1=form.luxury.field1.data,
                    field2=form.luxury.field2.data,
                    field3=form.luxury.field3.data,
                    field4=form.luxury.field4.data,
                    field5=form.luxury.field5.data,
                    field6=form.luxury.field6.data,)
        db.session.add(luxury)
        db.session.commit()
        flash('Your details have been submitted', 'luxury')
        return redirect(url_for('index'))

    return render_template('index.html', form=form)

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'

    return render_template('login.html' , form=form)

@app.route('/signup', methods=['GET','POST'])
def signup():
    form= RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1> New User has been created! </h1>'

    return render_template('signup.html',form=form)

@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html', name = current_user.username)

# RIP Good Coding Practices

@app.route('/dashboard/spa', methods=['GET','POST'])
@login_required
def spa():
    spas = Spa.query.all()
    return render_template('spa.html', name = current_user.username, spas=spas)

@app.route('/dashboard/saloon', methods=['GET','POST'])
@login_required
def saloon():
    saloons = Saloon.query.all()
    return render_template('saloon.html', name = current_user.username, saloons=saloons)

@app.route('/dashboard/car', methods=['GET','POST'])
@login_required
def car():
    cars = Car.query.all()
    return render_template('car.html', name = current_user.username, cars = cars)

@app.route('/dashboard/cloth', methods=['GET','POST'])
@login_required
def cloth():
    clothes = Cloth.query.all()
    return render_template('cloth.html', name = current_user.username, clothes=clothes)

@app.route('/dashboard/auto', methods=['GET','POST'])
@login_required
def auto():
    autos = Auto.query.all()
    return render_template('auto.html', name = current_user.username, autos = autos)

@app.route('/dashboard/house', methods=['GET','POST'])
@login_required
def house():
    houses = House.query.all()
    return render_template('house.html', name = current_user.username, houses = houses)

@app.route('/dashboard/luxury', methods=['GET','POST'])
@login_required
def luxury():
    luxuries = Luxury.query.all()
    return render_template('luxury.html', name = current_user.username, luxuries=luxuries)

@app.route("/dashboard/auto/delete", methods=["POST"])
def autodelete():
    id = request.form.get("id")
    auto = Auto.query.filter_by(id=id).first()
    db.session.delete(auto)
    db.session.commit()
    flash('Details have been deleted')
    return redirect("/dashboard/auto")

@app.route("/dashboard/spa/delete", methods=["POST"])
def spadelete():
    id = request.form.get("id")
    spa = Spa.query.filter_by(id=id).first()
    db.session.delete(spa)
    db.session.commit()
    flash('Details have been deleted')
    return redirect("/dashboard/spa")

@app.route("/dashboard/saloon/delete", methods=["POST"])
def saloondelete():
    id = request.form.get("id")
    saloon = Saloon.query.filter_by(id=id).first()
    db.session.delete(saloon)
    db.session.commit()
    flash('Details have been deleted')
    return redirect("/dashboard/saloon")

@app.route("/dashboard/car/delete", methods=["POST"])
def cardelete():
    id = request.form.get("id")
    car = Car.query.filter_by(id=id).first()
    db.session.delete(car)
    db.session.commit()
    flash('Details have been deleted')
    return redirect("/dashboard/car")

@app.route("/dashboard/cloth/delete", methods=["POST"])
def clothdelete():
    id = request.form.get("id")
    cloth = Cloth.query.filter_by(id=id).first()
    db.session.delete(cloth)
    db.session.commit()
    flash('Details have been deleted')
    return redirect("/dashboard/cloth")

@app.route("/dashboard/house/delete", methods=["POST"])
def housedelete():
    id = request.form.get("id")
    house = House.query.filter_by(id=id).first()
    db.session.delete(house)
    db.session.commit()
    flash('Details have been deleted')
    return redirect("/dashboard/house")

@app.route("/dashboard/luxury/delete", methods=["POST"])
def luxurydelete():
    id = request.form.get("id")
    luxury = Luxury.query.filter_by(id=id).first()
    db.session.delete(luxury)
    db.session.commit()
    flash('Details have been deleted')
    return redirect("/dashboard/luxury")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
