# Auth API

## Project Description

This project is a Node.js and Express authentication API backed by MongoDB.  
It supports user registration, access-token based authentication with JWT, and refresh-token rotation through secure HTTP-only cookies.  
The API exposes endpoints to register users, fetch the currently authenticated user, and refresh expired access tokens.

## Clone Repository

```bash
git clone https://github.com/ihossen016/Auth-System.git
cd Auth-System
```

## Local Setup

1. Install dependencies:

```bash
npm install
```

2. Create your environment file from the example:

```bash
cp .env.example .env
```

PowerShell alternative:

```powershell
Copy-Item .env.example .env
```

3. Update `.env` with your values:

```env
MONGODB_URI=your_mongodb_connection_string_here
JWT_SECRET=your_jwt_secret_key_here
```

4. Start the development server:

```bash
npm run dev
```

The server runs on `http://localhost:3000`.