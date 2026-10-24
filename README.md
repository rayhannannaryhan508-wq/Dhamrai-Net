# Dhamrai Net — Full-stack starter

This project is a real full-stack starting point, not a localStorage-only mockup. It uses:
- Node.js + Express backend
- PostgreSQL database
- bcrypt password hashing
- HttpOnly session cookie with JWT
- Role-protected admin APIs
- Client login, bill display, payment request submission, new connection applications, complaints and external speed-test links
- Admin customer creation, bill/package/status updates, payment review, connection status and complaint status

## Important: deployment/setup is still required
This ZIP is source code, not a live hosted website. To make it live, configure a PostgreSQL database and deploy the Node server on a Node-compatible host. Then set the environment variables below in the host dashboard.

## Required environment variables
- `DATABASE_URL`: PostgreSQL connection URL
- `JWT_SECRET`: long random secret (at least 32 characters)
- `ADMIN_PHONE`: admin login phone
- `ADMIN_PASSWORD`: choose a NEW strong password (at least 10 characters)
- `PAYMENT_NUMBER`: your confirmed bKash/Nagad/Rocket payment number
- `NODE_ENV=production`
- `PORT`: usually provided by the host

Never put the real `.env` file or secrets in a public repository. Do not share your deployment password, database password, or JWT secret in chat. Use a new admin password rather than any password previously shared in chat.

## First admin account
On first start, if `ADMIN_PHONE` and `ADMIN_PASSWORD` are configured and the phone is not already present, the app creates the admin account. The initial admin is not automatically overwritten on later starts.

## Local test
1. Install Node.js 20 or newer.
2. Create a PostgreSQL database.
3. Copy `.env.example` to `.env` and fill in your database URL, a random JWT secret, and a new admin password.
4. Run `npm install`
5. Run `npm start`
6. Open `http://localhost:3000`

## Deployment note
Use a host that supports a persistent Node.js web service and set all environment variables in its dashboard. The free tier/availability of hosts and databases can change, and some free services may sleep or have usage limits. For a public launch, test backups, access controls, error logs and recovery first.

## Security and operational notes
This is a useful starter, but it has not been independently security-audited. Before handling real payments/customer records, review security, add backup/monitoring, and test with dummy data. The app records payment requests for manual admin review; it does not automatically charge or verify mobile wallet payments. The speed-test links open FAST.com or Speedtest.net; they do not claim to measure speed inside this portal.
