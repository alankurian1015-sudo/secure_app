from app import app, db

if __name__ == '__main__':
    with app.app_context():
        from models import User
        import routes
        db.create_all()
    app.run(debug=True)