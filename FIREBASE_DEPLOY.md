# Bazar Afghanistan - Firebase Deployment

## Requirements

- Firebase project
- Firebase App Hosting
- GitHub repository
- PostgreSQL database
- Node.js 22

## Deployment

1. Push the project files to the GitHub `main` branch.
2. Open Firebase Console.
3. Open App Hosting.
4. Create a new backend.
5. Connect the GitHub repository.
6. Select the `main` branch.
7. Set the root directory to `/`.
8. Add the required environment variables.

## Required environment variables

DATABASE_URL
DATABASE_SSL
JWT_SECRET
COOKIE_SECURE
ADMIN_NAME
ADMIN_PHONE
ADMIN_PASSWORD
SETUP_ADMIN_SECRET

## Database

Run:

sql/schema.sql

against the PostgreSQL database before using the application.

## Important

Never put real passwords, database credentials, or secret keys inside GitHub files.
