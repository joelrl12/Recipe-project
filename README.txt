# Recipe Website

This is a web application for sharing and exploring recipes. 
Users can create an account, post recipes, review recipes, favorite recipes and more.


## Features

- **User Authentication**: Users can register, log in, and log out. Passwords are securely hashed.
- **Recipe Management**: Users can create, and delete their recipes.
- **Category Selection**: Users can choose from predefined categories when creating recipes.
- **Review System**: Users can rate and leave comments on recipes.
- **Favorites**: Users can add recipes to their favorites.

## Database

The application consists of five tables: User, Recipe, Review, favorite, and Category
User: Represents user data, including details like id, username, email, and relationships with other entities.
Category: Represents recipe categories.
Recipe: Represents recipe data, including details like id, title, user_id, category_id, instructions, and ingredients.
Review: Represents user reviews for recipes.
Favorite: Represents the association between users and their favorite recipes.

## Setup


1. **Create a Virtual Environment:**

    ```bash
    python -m venv venv
    ```

2. **Activate the Virtual Environment:**

    - On Windows:

        ```bash
        .\venv\Scripts\activate
        ```

    - On macOS/Linux:

        ```bash
        source venv/bin/activate
        ```

3. **Install Dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4. **Set Up the Database:**

    ```bash
    python manage.py db init
    python manage.py db migrate
    python manage.py db upgrade
    ```

5. **Run the Application:**

    ```bash
    python app.py
    ```

    The application will be accessible at [http://localhost:5000](http://localhost:5000).
