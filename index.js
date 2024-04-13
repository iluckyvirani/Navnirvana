import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import mongoose from 'mongoose';
import router from './router/route.js';
import dotenv from 'dotenv';

dotenv.config();

const app = express();

async function connect() {
    try {
        await mongoose.connect(process.env.MONGOOSE_URI);
        console.log("Database connected");
    } catch (error) {
        console.error("Error connecting to database:", error);
    }
}

// Middleware
app.use(express.json());
app.use(cors());
app.use(morgan('tiny'));
app.disable('x-powered-by'); // Less information exposed about the stack

const port = process.env.PORT || 5000; // Default port is 5000 if not provided in the environment variables

// Routes
app.get('/', (req, res) => {
    res.status(201).json("GET request");
});

app.use('/api', router);

// Start server only when we have a valid database connection
connect().then(() => {
    app.listen(port, () => {
        console.log(`Server connected to http://localhost:${port}`);
    });
}).catch(error => {
    console.error("Invalid database connection:", error);
});
