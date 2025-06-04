# Deploying SecureChat to Vercel

This guide explains how to deploy the SecureChat application to Vercel.

## Prerequisites

1. A [Vercel](https://vercel.com/) account
2. [Vercel CLI](https://vercel.com/docs/cli) (optional, for local testing)
3. [Git](https://git-scm.com/) installed on your machine

## Deployment Steps

### 1. Prepare Your Repository

Make sure your code is in a Git repository:

```bash
git init
git add .
git commit -m "Initial commit"
```

### 2. Deploy to Vercel

#### Option 1: Using the Vercel Dashboard

1. Go to [Vercel Dashboard](https://vercel.com/dashboard)
2. Click "New Project"
3. Import your Git repository (from GitHub, GitLab, or Bitbucket)
4. Configure the project:
   - Framework Preset: Other
   - Build Command: Leave empty
   - Output Directory: Leave empty
   - Install Command: `pip install -r requirements.txt`
5. Add Environment Variables (optional):
   - `SECRET_KEY`: A strong random key for Flask sessions
   - `DB_NAME`: Name of your database file (default: users.db)
6. Click "Deploy"

#### Option 2: Using Vercel CLI

1. Install Vercel CLI:
   ```bash
   npm i -g vercel
   ```

2. Login to Vercel:
   ```bash
   vercel login
   ```

3. Deploy the application:
   ```bash
   vercel
   ```

4. Follow the interactive prompts to configure your project

### 3. Configure Environment Variables

After deployment, you can add or modify environment variables in the Vercel dashboard:

1. Go to your project in the Vercel dashboard
2. Click on "Settings" > "Environment Variables"
3. Add the following variables:
   - `SECRET_KEY`: A strong random key for Flask sessions
   - `DB_NAME`: Name of your database file (default: users.db)

### 4. Database Considerations

Vercel's serverless functions run in an ephemeral environment, which means:

- The SQLite database will be reset on each deployment
- For a production app, consider using a persistent database service like:
  - [Vercel Postgres](https://vercel.com/docs/storage/vercel-postgres)
  - [Supabase](https://supabase.com/)
  - [MongoDB Atlas](https://www.mongodb.com/cloud/atlas)

### 5. Troubleshooting

If you encounter issues:

1. Check the Vercel deployment logs in the dashboard
2. Ensure all dependencies are in `requirements.txt`
3. Verify that your Python version is compatible (we're using Python 3.9)
4. Check for any serverless function size limits (your code might need optimization)

### 6. Custom Domain (Optional)

To use a custom domain:

1. Go to your project in the Vercel dashboard
2. Click on "Settings" > "Domains"
3. Add your domain and follow the instructions to set up DNS

## Limitations

When running on Vercel, be aware of these limitations:

1. **WebSockets**: Socket.IO may not work fully in serverless mode. Consider using HTTP polling as a fallback.
2. **File System**: The filesystem is read-only except for `/tmp`.
3. **Execution Time**: Functions have a maximum execution duration.
4. **Cold Starts**: There might be delays when functions haven't been used recently.

## Local Testing

To test your Vercel deployment locally:

```bash
vercel dev
```

This will simulate the Vercel environment on your local machine. 