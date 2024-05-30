from src import create_app
from src import cleanup

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, port=9696)

