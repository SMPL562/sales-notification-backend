# Sales Notification Backend

## **Overview**

The **Sales Notification Backend** is a *Node.js/Express* application that powers the Sales Notification Chrome Extension for *~300 Business Development Executives (BDEs)* at **Coding Ninjas**. It handles **real-time notifications** via *WebSocket*, **user authentication** via *OTP*, and **webhook integration** with *LeadSquared*. The backend is deployed on **Render** (`https://sales-notification-backend.onrender.com`) and uses *SendGrid* for sending OTP emails.

## **Features**

- **Real-Time Notifications**:
  - Receives webhook payloads from *LeadSquared* (`/webhook`) and broadcasts them to connected Chrome extension clients via *WebSocket*.
  - Supports three notification types:
    - **`sale_made`**: Sale notifications with BDE name, product, and manager name.
    - **`notification`**: General announcements.
    - **`private`**: Private messages for specific users (based on email).
- **User Authentication**:
  - Generates and sends OTPs to `@codingninjas.com` emails (`/request-otp`).
  - Verifies OTPs and issues a UUID token (`/verify-otp`).
- **Security**:
  - Webhook endpoint secured with a **Bearer token** (`WEBHOOK_TOKEN`).
  - API endpoints (`/request-otp`, `/verify-otp`) and WebSocket connections secured with **token-based authentication** (UUID).
  - **CORS** and WebSocket origin validation restricted to the Chrome extension’s origin.
  - **Rate limiting** on API endpoints to prevent abuse.
  - WebSocket connection limiting per IP.

## **Files**

| **File**       | **Description**                                      |
|----------------|------------------------------------------------------|
| `server.js`    | Main backend application with Express, WebSocket, and API endpoints. |
| `package.json` | Defines dependencies and scripts for the backend.   |
| `Procfile`     | Configures Render deployment (`web: node server.js`). |
| `.env`         | Stores environment variables for local development (not committed to version control). |

## **Dependencies**

- **`express`**: Web framework for Node.js.
- **`http`**: Core Node.js module for creating the server.
- **`ws`**: WebSocket library for real-time communication.
- **`@sendgrid/mail`**: SendGrid client for sending OTP emails.
- **`cors`**: Middleware for enabling CORS with origin restrictions.
- **`uuid`**: Generates UUID tokens for authentication.
- **`express-rate-limit`**: Rate limiting middleware to prevent abuse.
- **`dotenv`**: Loads environment variables from a `.env` file (local development).

## **Setup Instructions**

### **Prerequisites**

- **Node.js** (v14 or higher) installed for local development.
- A **Render** account for deployment (`https://render.com`).
- A **SendGrid** account with an API key for sending emails.
- A **LeadSquared** account to send webhook notifications.

### **Local Development**

1. **Clone the Repository**:
   - Clone the repository to your local machine:
     ```bash
     git clone <repository-url>
     cd sales-notification-backend
     ```
2. **Install Dependencies**:
   - Run:
     ```bash
     npm install
     ```
3. **Set Up Environment Variables**:
   - Create a `.env` file in the root directory and add the following:
     ```env
     SENDGRID_API_KEY=your-sendgrid-api-key
     WEBHOOK_TOKEN=your-webhook-token
     EXTENSION_ID=your-chrome-extension-id
     PORT=3000
     ```
     - **`SENDGRID_API_KEY`**: Your SendGrid API key.
     - **`WEBHOOK_TOKEN`**: A secure token for LeadSquared webhook authentication (e.g., `w1x2y3z4a5b6c7d8e9f0g1h2i3j4k5l6`).
     - **`EXTENSION_ID`**: Your Chrome extension ID (e.g., `abcdefghijkmlnopqrstuvwxyzabcdef`).
     - **`PORT`**: The port to run the server on (default: 3000).
4. **Run the Server**:
   - Start the server:
     ```bash
     npm start
     ```
   - The server will run on `http://localhost:3000`.

### **Deployment on Render**

1. **Create a Render Service**:
   - Log in to Render (`https://dashboard.render.com`).
   - Create a new **Web Service** and connect your repository.
2. **Set Environment Variables**:
   - In the Render dashboard, go to the “Environment” tab for your service.
   - Add the following variables:
     - **`SENDGRID_API_KEY`**: Your SendGrid API key.
     - **`WEBHOOK_TOKEN`**: A secure token for webhook authentication (e.g., `w1x2y3z4a5b6c7d8e9f0g1h2i3j4k5l6`).
     - **`EXTENSION_ID`**: Your Chrome extension ID (e.g., `abcdefghijkmlnopqrstuvwxyzabcdef`).
     - **`PORT`**: Set to `3000` (Render default).
3. **Deploy**:
   - Render will automatically deploy using the `Procfile` (`web: node server.js`).
   - The backend will be accessible at `https://sales-notification-backend.onrender.com`.

### **Configure LeadSquared Webhook**

1. Log in to your **LeadSquared** account.
2. Navigate to **Webhook settings** (e.g., under Automation or Integration).
3. Configure the webhook:
   - **URL**: `https://sales-notification-backend.onrender.com/webhook`
   - **Method**: POST
   - **Headers**:
     - `Authorization`: `Bearer <WEBHOOK_TOKEN>` (replace with the `WEBHOOK_TOKEN` set in Render).
     - `Content-Type`: `application/json`
   - **Payload Examples**:
     - **Sale Made**:
       ```json
       {
         "type": "sale_made",
         "bdeName": "Chinmay Ramraika",
         "product": "Job Bootcamp Data Analytics",
         "managerName": "Business Team"
       }
       ```
     - **Notification**:
       ```json
       {
         "type": "notification",
         "message": "Team meeting at 3 PM"
       }
       ```
     - **Private Message**:
       ```json
       {
         "type": "private",
         "email": "user@codingninjas.com",
         "message": "Reminder: Submit your report"
       }
       ```
4. Save the webhook configuration.

## **API Endpoints**

### **`POST /request-otp`**

- **Description**: Generates and sends an OTP to a `@codingninjas.com` email.
- **Request Body**:
  ```json
  { "email": "user@codingninjas.com" }
  ```
- **Headers**:
  - `Authorization: Bearer <token>` *(optional for first request, required for subsequent requests)*.
- **Responses**:
  - `200`: `{"message":"OTP sent successfully"}`
  - `400`: `{"error":"Invalid email. Must be @codingninjas.com"}`
  - `401`: `{"error":"Unauthorized: Missing or invalid Bearer token"}` *(if token is required and missing/invalid)*.
  - `500`: `{"error":"Failed to send OTP"}`

### **`POST /verify-otp`**

- **Description**: Verifies the OTP and returns a UUID token for authentication.
- **Request Body**:
  ```json
  { "email": "user@codingninjas.com", "otp": "123456" }
  ```
- **Headers**:
  - `Authorization: Bearer <token>` *(required)*.
- **Responses**:
  - `200`: `{"message":"OTP verified successfully","token":"<uuid>","email":"user@codingninjas.com"}`
  - `400`: `{"error":"Invalid or expired OTP"}`
  - `401`: `{"error":"Unauthorized: Missing or invalid Bearer token"}`

### **`POST /webhook`**

- **Description**: Receives notifications from LeadSquared and broadcasts them to WebSocket clients.
- **Request Body**: See payload examples in LeadSquared configuration.
- **Headers**:
  - `Authorization: Bearer <WEBHOOK_TOKEN>`
  - `Content-Type: application/json`
- **Responses**:
  - `200`: `{"message":"Webhook received successfully"}`
  - `400`: `{"error":"Missing type field"}`
  - `401`: `{"error":"Unauthorized: Missing or invalid Bearer token"}`

### **`GET /ping`**

- **Description**: Keeps Render awake.
- **Response**:
  - `200`: `{"status":"alive"}`

## **WebSocket**

- **URL**: `wss://sales-notification-backend.onrender.com/ws?token=<token>`
- **Authentication**: Requires a `token` (UUID) query parameter, obtained from `/verify-otp`.
- **Messages**:
  - **Ping/Pong**: The extension sends `{"type":"ping"}` every 30 seconds, and the backend responds with `{"type":"pong"}`.
  - **Notifications**: The backend broadcasts payloads received from `/webhook` (e.g., `sale_made`, `notification`, `private`).

## **Security Features**

- **Token Authentication**:
  - API endpoints (`/request-otp`, `/verify-otp`) and WebSocket connections use a **UUID token** generated by `/verify-otp`.
  - `/request-otp` allows first-time requests without a token but requires a token for subsequent requests.
- **Webhook Authentication**:
  - Secured with `WEBHOOK_TOKEN`, sent as `Bearer <WEBHOOK_TOKEN>` in the `Authorization` header.
- **CORS and Origin Validation**:
  - **CORS** restricts API requests to `chrome-extension://${EXTENSION_ID}`.
  - WebSocket connections are restricted to the same origin.
- **Rate Limiting**:
  - API endpoints (`/request-otp`, `/verify-otp`) are limited to **100 requests per IP per 15 minutes**.
  - WebSocket connections are limited to **5 per IP**.
- **Environment Variables**:
  - `SENDGRID_API_KEY`, `WEBHOOK_TOKEN`, and `EXTENSION_ID` are stored in **Render’s environment variables**, ensuring sensitive values are not hardcoded.

## **Limitations**

- OTPs are stored in-memory (`otps` Map) and lost on server restart. Consider using a database (e.g., **MongoDB**) for persistence in production.
- Rate limiting is IP-based, which may affect users behind shared IPs (e.g., corporate networks).
