import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

/** Auth middleware */
export default async function Auth(req, res, next) {
    try {
        // Check if the Authorization header exists and is in the correct format
        const authorizationHeader = req.headers.authorization;
        if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Authorization header missing or incorrect format' });
        }

        // Extract token from the header
        const token = authorizationHeader.split(' ')[1];

        // Verify the token and retrieve user details
        const decodedToken = await jwt.verify(token, process.env.JWT_SECRET);

        // Ensure the decoded token contains the required user ID
        if (!decodedToken || !decodedToken.userId) {
            return res.status(401).json({ error: 'Invalid token' });
        }

        // Attach user information to the request object
        req.user = {
            id: decodedToken.userId,
            ...decodedToken // Attach additional properties as needed
        };

        // Proceed to the next middleware function
        next();
    } catch (error) {
        // Log the error if necessary
        console.error('Authentication error:', error);

        // Handle errors by sending a 401 Unauthorized status
        res.status(401).json({ error: 'Authentication failed' });
    }
}

/** Local variables middleware */
export function localVariables(req, res, next) {
    req.app.locals = {
        OTP: null,
        resetSession: false
    };
    next();
}
