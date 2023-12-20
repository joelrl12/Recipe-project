from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Integer, String, Column

from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, IntegerField, SubmitField, ValidationError, DecimalField, Form, FormField, SelectField, TextAreaField, FieldList
from wtforms.validators import DataRequired, EqualTo, Length, NumberRange
from flask_bcrypt import Bcrypt

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
bcrypt = Bcrypt(app)
class Base(DeclarativeBase):
    pass
db = SQLAlchemy(model_class=Base)

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:nathan2004@localhost/recipeProject"
app.config["SECRET_KEY"] = 'supersecretcode'
db.init_app(app)
########################   db models   ############################
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    recipes = db.relationship('Recipe', backref='author', lazy=True)
    reviews = db.relationship('Review', backref='author', lazy=True)
    favorites = db.relationship('Favorite', backref='user', lazy=True)

    def create_recipe(self, title, category_id, instructions, ingredients):
        new_recipe = Recipe(
            title=title,
            user_id=self.id,
            category_id=category_id,
            instructions=instructions,
            ingredients=ingredients 
        )

        # Commit changes to the database
        db.session.add(new_recipe)
        db.session.commit()

        return new_recipe
    
    def has_favorited(self, recipe):
        return Favorite.query.filter_by(user_id=self.id, recipe_id=recipe.id).first() is not None


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category_name = db.Column(db.String(50), unique=True, nullable=False)
    recipes = db.relationship('Recipe', backref='category', lazy=True)

class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    instructions = db.Column(db.Text, nullable=False)
    ingredients = db.Column(db.String, nullable=False) 
    reviews = db.relationship('Review', backref='recipe', lazy=True)
    favorites = db.relationship('Favorite', backref='recipe', lazy=True)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipe.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)

class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipe.id'), nullable=False)
    db.UniqueConstraint('user_id', 'recipe_id')

def initialize_categories():
    # List of category names to add
    category_names = ['Breakfast', 'Lunch', 'Dinner', 'Dessert', 'Snack', 'Beverage']
    categorys = Category.query.all()
    if(categorys):
        return
    else:
    # Add categories to the database
        for category_name in category_names:
            category = Category(category_name=category_name)
            db.session.add(category)
        db.session.commit()

with app.app_context():
    db.create_all()
    initialize_categories()

########################   forms   ############################
    
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField('Password', validators=[DataRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField('Password', validators=[DataRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    email = StringField('Email', validators=[DataRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Email"})
    submit = SubmitField('Register')
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
        username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. choose a different one.")
    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError("That email is already registered. Choose a different one.")


class RecipeForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    category = SelectField('Category', coerce=int, validators=[DataRequired()])
    instructions = TextAreaField('Instructions', validators=[DataRequired()])
    ingredients = TextAreaField('Ingredients', validators=[DataRequired()])
    submit = SubmitField('Create Recipe')

class ReviewForm(FlaskForm):
    rating = IntegerField('Rating', validators=[DataRequired(), NumberRange(min=1, max=10)])
    comment = TextAreaField('Comment')
    submit = SubmitField('Submit Review')

########################   routes   ############################

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/logout', methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/dashboard', methods=["GET", "POST"])
@login_required
def dashboard():
    user = current_user
    favorites = Favorite.query.filter_by(user_id=user.id).all()
    return render_template('dashboard.html')

@app.route('/create_recipe', methods=['GET', 'POST'])
@login_required
def create_recipe():
    form = RecipeForm()
    # let user choose from the existing categories
    form.category.choices = [(category.id, category.category_name) for category in Category.query.all()]

    if form.validate_on_submit():
        title = form.title.data
        category_id = form.category.data
        instructions = form.instructions.data
        ingredients = form.ingredients.data

        # Use the create_recipe method to add the new recipe to the database
        new_recipe = current_user.create_recipe(
            title=title,
            category_id=category_id,
            instructions=instructions,
            ingredients=ingredients
        )

        # Commit changes to the database
        db.session.commit()

        flash(f'Recipe "{new_recipe.title}" created successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('create_recipe.html', form=form)

@app.route('/recipes', methods=['GET'])
def recipes():
    recipes = Recipe.query.all()
    return render_template('recipes.html', recipes=recipes)

@app.route('/recipe/<int:recipe_id>')
def recipe_details(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)
    reviews = Review.query.filter_by(recipe_id=recipe_id).all()


    # Get the associated user using the user_id
    author = User.query.get(recipe.user_id)
    if author:
        author_name = author.username
    else:
        # Handle the case where the user is not found (optional)
        author_name = "Unknown Author"

    review_form = ReviewForm()

    is_favorited = False
    if current_user.is_authenticated:
        favorite = Favorite.query.filter_by(user_id=current_user.id, recipe_id=recipe.id).first()
        is_favorited = favorite is not None

    return render_template('recipe_details.html', author_name=author_name, recipe=recipe, reviews=reviews, review_form=review_form, is_favorited=is_favorited)

@app.route('/recipe/<int:recipe_id>/delete', methods=['POST'])
@login_required
def delete_recipe(recipe_id):
    # get the recipe frrom the database
    recipe = Recipe.query.get_or_404(recipe_id)

    # Check if the current user is the author of the recipe
    if current_user.id != recipe.user_id:
        flash("You don't have permission to delete this recipe.", 'danger')
        return redirect(url_for('dashboard'))

    db.session.delete(recipe)
    db.session.commit()

    flash('Recipe deleted successfully!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/recipe/<int:recipe_id>/submit_review', methods=['POST'])
@login_required
def submit_review(recipe_id):
    # Check if the user has already submitted a review for this recipe
    existing_review = Review.query.filter_by(user_id=current_user.id, recipe_id=recipe_id).first()
    form = ReviewForm()
    if form.validate_on_submit():
        if existing_review:
            flash('You have already submitted a review for this recipe.', 'warning')
            return redirect(url_for('recipe_details', recipe_id=recipe_id))

        new_review = Review(
            user_id=current_user.id,
            recipe_id=recipe_id,
            rating=form.rating.data,
            comment=form.comment.data
        )
        # Add review to the database 
        db.session.add(new_review)
        db.session.commit()
        flash('Review submitted successfully!', 'success')
    else:
        flash('Error submitting review. Please check your inputs.', 'danger')

    return redirect(url_for('recipe_details', recipe_id=recipe_id))

@app.route('/toggle_favorite/<int:recipe_id>', methods=['POST'])
@login_required
def toggle_favorite(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)
    user = current_user

    # Check if the user has already favorited the recipe
    favorite = Favorite.query.filter_by(user_id=user.id, recipe_id=recipe.id).first()

    if favorite:
        # If already favorited, remove it
        db.session.delete(favorite)
        db.session.commit()
        flash(f'Recipe "{recipe.title}" removed from favorites!', 'success')
    else:
        # If not favorited, add it
        new_favorite = Favorite(user_id=user.id, recipe_id=recipe.id)
        db.session.add(new_favorite)
        db.session.commit()
        flash(f'Recipe "{recipe.title}" added to favorites!', 'success')

    return redirect(url_for('dashboard'))

@app.route('/favorites', methods=['GET'])
@login_required
def favorites():
    user = current_user
    # Show all recipes user has favorited
    favorites = Favorite.query.filter_by(user_id=user.id).all()
    return render_template('favorites.html', favorites=favorites)

# Route for About Us
@app.route('/about_us')
def about_us():
    return render_template('about_us.html')

# Route for Terms of Service
@app.route('/terms_of_service')
def terms_of_service():
    return render_template('terms_of_service.html')

if __name__ == '__main__':
    app.run(debug=True)
    