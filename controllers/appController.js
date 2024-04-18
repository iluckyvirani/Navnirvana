import userModel from "../model/user.model.js";
import adminModel from "../model/adminmodel.js";
import ContactRequest from '../model/CallRequest.js';
import bcrypt from 'bcrypt';
import jwt from "jsonwebtoken";
import bodyParser from 'body-parser';
import dotenv from 'dotenv';
import otpGenerator from 'otp-generator';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import { timeStamp } from "console";
dotenv.config();
/** middleware for verify user */
export async function verifyUser(req, res, next) {
    try {

        const { phone } = req.method == "GET" ? req.query : req.body;

        // check the user existance
        let exist = await userModel.findOne({ phone });
        if (!exist) return res.status(404).send({ error: "Can't find User!" });
        next();

    } catch (error) {
        return res.status(404).send({ error: "Authentication Error" });
    }
}



// Function to send OTP to user's email
async function sendOTPEmail(email, otp) {
    // Create a Nodemailer transporter
    let transporter = nodemailer.createTransport({
        // service: 'Gmail',
        // auth: {
        //     user: 'your-email@gmail.com', // Your email address
        //     pass: 'your-email-password' // Your email password
        // }

        service: 'Gmail',
        port: 587,
        auth: {
            user: "contactus@navnirvana.com",
            pass: "tijz mhxn odew cfby"
        }
    });

    // email message 
    let mailOptions = {
        from: '"NavNirvana" <contactus@navnirvana.com>',
        to: email,
        subject: 'OTP Verification',
        text: `Your OTP for registration is: ${otp}`
    };

    // Send email
    try {
        await transporter.sendMail(mailOptions);
        console.log('OTP email sent successfully.');
    } catch (error) {
        console.error('Error sending OTP email:', error);
        throw new Error('Error sending OTP email');
    }
}


//Function to send otp to user's email while login
async function LoginOTPEmail(email, otp) {
    // Create a Nodemailer transporter
    let transporter = nodemailer.createTransport({
        // service: 'Gmail',
        // auth: {
        //     user: 'your-email@gmail.com', // Your email address
        //     pass: 'your-email-password' // Your email password
        // }

        service: 'Gmail',
        port: 587,
        auth: {
            user: "contactus@navnirvana.com",
            pass: "tijz mhxn odew cfby"
        }
    });

    // email message 
    let mailOptions = {
        from: '"NavNirvana" <contactus@navnirvana.com>',
        to: email,
        subject: 'OTP Verification',
        text: `Your OTP for Login : ${otp}`
    };

    // Send email
    try {
        await transporter.sendMail(mailOptions);
        console.log('OTP email sent successfully.');
    } catch (error) {
        console.error('Error sending OTP email:', error);
        throw new Error('Error sending OTP email');
    }
}




/** POST :http://localhost:5000/api/register
//  * @param {
//  * "name":"shivangi",
//  * "phone":"9450490471",
//  * "email":"shiv123@gmail.com",
//  * "password":"shi1234"
//  * 
//  * 
//  * } 
 
 */

// Function to generate random 6-digit OTP along with timestamp
function generateOTP() {
    // Generate a random 6-digit number for the OTP
    const otp = Math.floor(100000 + Math.random() * 900000);

    // Get the current date and time
    const timestamp = new Date();

    // Format the timestamp in a human-readable format
    const formattedTimestamp = timestamp.toLocaleString();

    // Return OTP and formatted timestamp as an object
    return { otp: otp.toString(), timestamp: formattedTimestamp };
}

export async function register(req, res) {
    try {
        const { name, phone, email, password } = req.body;

        // Check for existing user
        const existingUser = await userModel.findOne({ phone });
        if (existingUser) {
            return res.status(400).json({ error: "Please use a different phone." });
        }

        // Check for existing email
        const existingEmail = await userModel.findOne({ email });
        if (existingEmail) {
            return res.status(400).json({ error: "Please use a different email address." });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Generate OTP and timestamp
        const { otp, timestamp } = generateOTP();

        // After generating OTP, send email to the user
        await sendOTPEmail(email, otp);
        // console.log(timestamp)
        // Create new user with OTP and timestamp
        const newUser = new userModel({
            name,
            email,
            phone,
            password: hashedPassword,
            verifyOTP: otp,
            OTPtimeperiod: timestamp
        });

        // Save user to database
        await newUser.save();

        return res.status(201).json({ message: "User registered successfully.", OTP: otp });
    } catch (error) {
        console.error("Error:", error);
        return res.status(500).json({ error: "Internal server error." });
    }
}


/** POST :http://localhost:5000/api/login
//  * @param {
    //  * "phone":"9450490471"
    //  * "password":"shi1234"
  
    //  * } 
     
     */

export async function login(req, res) {
    const { phone, password } = req.body;

    try {
        // Find user by phone number
        const user = await userModel.findOne({ phone });

        // Check if user exists
        if (!user) {
            return res.status(404).json({ error: "Phone number not found" });
        }

        // Validate password
        const passwordValid = await bcrypt.compare(password, user.password);
        if (!passwordValid) {
            return res.status(400).json({ error: "Incorrect password" });
        }

        // Generate OTP and timestamp
        const { otp, timestamp } = generateOTP();

        // Send OTP to the user via email
        await sendOTPEmail(user.email, otp);

        // Generate JWT token
        const token = jwt.sign({
            userId: user._id,
            phone: user.phone
        }, process.env.JWT_SECRET, {
            expiresIn: "24h"
        });

        // Return success response with token
        return res.status(200).json({
            message: "Login successful.",
            data: {
                phone: user.phone,
                Email:user.email,
                token
            }
        });
    } catch (error) {
        console.error("Error during login:", error);
        return res.status(500).json({ error: "Internal server error" });
    }
}


/** GET :http://localhost:5000/api/user/name
//  * @param {
    //  * "name":"shivangi",
    //  * "phone":"9450490471",
    //  * "email":"shiv123@gmail.com",
    //  * "password":"shi1234"
    //  * 
    //  * 
    //  * } 
     
     */
export async function getuser(req, res) {
    const { name } = req.params;

    try {
        if (!name) {
            return res.status(400).send({ error: "Invalid name parameter" });
        }

        const user = await userModel.findOne({ name });

        if (!user) {
            return res.status(404).send({ error: "User not found" });
        }

        /** remove password from user */
        // mongoose return unnecessary data with object so convert it into json
        const { password, ...rest } = Object.assign({}, user.toJSON());

        return res.status(200).send(user);
    } catch (error) {
        console.error("Error:", error);
        return res.status(500).send({ error: "Internal server error" });
    }
}



/** PUT :http://localhost:5000/api/user/updateuser
//  * @param {
//  "id":"<userid>"

//  * } 
body:{
    "name":"",
    "phone":"",
    "email":"",
    "password":""
}
 
 */

export async function updateUser(req, res) {
    try {
        if (req.body) {
            console.log(req.body);
            const userId = req?.body?.id;

            if (!userId) {
                return res.status(401).send({ error: "Unauthorized access" });
            }

            const body = req.body;
            const id = req.body.id;

            // Update the data using Mongoose's Promise-based API
            const updatedUser = await userModel.updateOne({ _id: id }, body);

            if (updatedUser.nModified === 0) {
                return res.status(404).send({ error: "User not found or no modifications made" });
            }

            const updatedUserData = await userModel.findOne({ _id: id });
            return res.status(200).send({ msg: "Record updated successfully", data: updatedUserData });
        }
    } catch (error) {
        console.error("Error updating user:", error);
        return res.status(500).send({ error: "Internal server error" });
    }
}


/** GET :http://localhost:5000/api/generateOTP */

export async function generatepasswordOTP(req, res) {

    req.app.locals.OTP = await otpGenerator.generate(6, { lowerCaseAlphabets: false, upperCaseAlphabets: false, specialChars: false })
    res.status(201).send({ code: req.app.locals.OTP })

}

/** GET :http://localhost:5000/api/verifyOTP */
export async function verifyOTP(req, res) {
    try {
        const { verifyOTP, email } = req.body;

        // Find user by email
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: "User not found or OTP is incorrect." });
        }

        // Check if OTP is correct
        if (user.verifyOTP !== verifyOTP) {
            return res.status(400).json({ error: "Invalid OTP." });
        }

        // Check if OTP is expired
        const currentTime = new Date();
        const otpExpiration = new Date(user.otpCreatedAt);
        otpExpiration.setHours(otpExpiration.getHours() + 48); // OTP expires after 48 hours

        if (currentTime > otpExpiration) {
            return res.status(400).json({ error: "OTP has expired. Please request a new OTP." });
        }

        // Update user's email verification status
        user.isemailverify = true;
        await user.save();

        return res.status(200).json({ message: "Email verified successfully." });
    } catch (error) {
        console.error("Error:", error);
        return res.status(500).json({ error: "Internal server error." });
    }
}



//update the password when we have valid session
/** PUT :http://localhost:5000/api/resetPassword */
export async function resetPassword(req, res) {
    try {
        const { email } = req.body;

        // Find user by email
        const user = await userModel.findOne({ email });

        if (!user) {
            console.log("User not found:", email);
            return res.status(404).send({ error: "User not found" });
        }

        // Verify reset token
        // if (user.resetToken !== resetToken) {
        //     console.log("Invalid reset token for user:", email);
        //     return res.status(400).send({ error: "Invalid reset token" });
        // }

        // Generate a unique reset token
        const newResetToken = generateResetToken();

        // Save the new reset token to the user's document
        user.resetToken = newResetToken;
        await user.save();

        // Send email with reset link containing the new reset token
        await sendPasswordResetEmail(email, newResetToken);

        console.log("Password reset OTP sent to:", email);
        return res.status(200).send({ message: "Password reset OTP sent successfully" });
    } catch (error) {
        console.error("Error:", error);
        return res.status(500).send({ error: "Internal server error" });
    }
}



export async function updatePassword(req, res) {
    try {
        const { email, resetToken, newPassword } = req.body;

        // Find the user by email and reset token
        const user = await userModel.findOne({ email, resetToken });

        // Check if the user exists
        if (!user) {
            console.log("No user found or invalid reset token for email:", email);
            return res.status(404).send({ error: "User not found or invalid reset token" });
        }

        // Verify that the provided reset token matches the one stored in the database
        if (user.resetToken !== resetToken) {
            console.log("Provided reset token does not match the stored token for email:", email);
            return res.status(400).send({ error: "Invalid reset token" });
        }

        // Hash the new password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        // Update the user's password and clear the reset token
        user.password = hashedPassword;
        user.resetToken = undefined; // Clear the reset token

        // Save the updated user document
        await user.save();

        console.log("Password updated successfully for user:", email);
        return res.status(200).send({ message: "Password updated successfully" });
    } catch (error) {
        console.error("Error updating password:", error);
        return res.status(500).send({ error: "Internal server error" });
    }
}

// Function to generate a unique reset token
function generateResetToken() {

    const otp = Math.floor(100000 + Math.random() * 900000); // Generate a random number between 100000 and 999999
    return otp.toString();

}


// Function to send password reset email
async function sendPasswordResetEmail(email, resetToken) {
    try {
        // Create a Nodemailer transporter using SMTP transport
        const transporter = nodemailer.createTransport({
            service: 'gmail', // e.g., 'gmail'
            auth: {
                user: 'contactus@navnirvana.com',
                pass: 'tijz mhxn odew cfby',
            },
        });

        // Define email options
        const mailOptions = {
            from: '"NavNirvana" <contactus@navnirvana.com',
            to: email,
            subject: 'Password Reset OTP',
            html: `
                <p>Hello,</p>
                <p>You have requested to reset your password. Please enter OTP to reset your password:</p>
                <span>${resetToken}  Reset Password</span>
                <p>If you did not request this, please ignore this email.</p>
                <p>Best regards,</p>
                <p>Your Website Team</p>
            `,
        };

        // Send the email
        await transporter.sendMail(mailOptions);

        console.log('Password reset email sent successfully.');
    } catch (error) {
        console.error('Error sending password reset email:', error);
        throw error;
    }
}

//  GET :http://localhost:5000/api/getalluser
export async function getAllUsers(req, res) {
    try {
        const users = await userModel.find();

        if (!users || users.length === 0) {
            return res.status(404).send({ error: "No users found" });
        }

        // Remove passwords from users
        const usersWithoutPasswords = users.map(user => {
            const { password, ...rest } = Object.assign({}, user.toJSON());
            return rest;
        });

        return res.status(200).send(usersWithoutPasswords);
    } catch (error) {
        console.error("Error:", error);
        return res.status(500).send({ error: "Internal server error" });
    }
}










// Admin 



export async function verifyAdmin(req, res, next) {
    try {

        const { phone } = req.method == "GET" ? req.query : req.body;

        // check the user existance
        let exist = await adminModel.findOne({ phone });
        if (!exist) return res.status(404).send({ error: "Can't find User!" });
        next();

    } catch (error) {
        return res.status(404).send({ error: "Authentication Error" });
    }
}





export async function adminregister(req, res) {
    try {
        const { name, phone, email, password } = req.body;

        // Check for existing user
        const existingUser = await adminModel.findOne({ phone });
        if (existingUser) {
            return res.status(400).json({ error: "Please use a different phone." });
        }

        // Check for existing email
        const existingEmail = await adminModel.findOne({ email });
        if (existingEmail) {
            return res.status(400).json({ error: "Please use a different email address." });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);



        // Create new user with OTP
        const newUser = new adminModel({
            name,
            email,
            phone,
            password: hashedPassword,

        });

        // Save user to database
        await newUser.save();

        return res.status(201).json({ message: "Admin registered successfully." });
    } catch (error) {
        console.error("Error:", error);
        return res.status(500).json({ error: "Internal server error." });
    }
}



/** POST :http://localhost:5000/api/login
//  * @param {
    //  * "phone":"9450490471"
    //  * "password":"shi1234"
  
    //  * } 
     
     */

export async function adminlogin(req, res) {
    const { phone, password } = req.body;

    try {
        // Find the admin by phone number
        const admin = await adminModel.findOne({ phone });
        if (!admin) {
            return res.status(404).send({ error: "Phone number not found" });
        }

        // Compare the provided password with the stored password
        const passwordCheck = await bcrypt.compare(password, admin.password);
        if (!passwordCheck) {
            return res.status(400).send({ error: "Incorrect password" });
        }

        // Generate JWT token
        const token = jwt.sign({
            userId: admin._id,
            phone: admin.phone
        }, process.env.JWT_SECRET, { expiresIn: "24h" });

        // Generate OTP (optional)
        const otp = otpGenerator.generate(6, { upperCase: false, specialChars: false });

        // TODO: Send OTP to the user via SMS or email

        // Send a successful response with the token and optionally, the OTP
        return res.status(200).send({
            msg: "Login successful.",
            token,
        });
    } catch (error) {
        console.error("Error during admin login:", error);
        return res.status(500).send({ error: "Internal server error" });
    }
}

//  GET :http://localhost:5000/api/getalluser
export async function getAllAdmin(req, res) {
    try {
        const users = await adminModel.find();

        if (!users || users.length === 0) {
            return res.status(404).send({ error: "No users found" });
        }

        // Remove passwords from users
        const usersWithoutPasswords = users.map(user => {
            const { password, ...rest } = Object.assign({}, user.toJSON());
            return rest;
        });

        return res.status(200).send(usersWithoutPasswords);
    } catch (error) {
        console.error("Error:", error);
        return res.status(500).send({ error: "Internal server error" });
    }
}





// call request


export async function createContactRequest(req, res) {
    try {
        // Destructure `category` and `comment` from the request body
        const { category, comment } = req.body;
        // Extract the user ID from the authenticated user
        const userId = req.user.id;

        // Log inputs for debugging
        console.log('userId:', userId);
        console.log('category:', category);
        console.log('comment:', comment);

        // Validate inputs
        if (!category || !comment) {
            throw new Error('Missing required fields: category and comment');
        }

        // Create a new contact request object
        const newContactRequest = new ContactRequest({
            userId,
            category,
            comment,
        });

        // Save the new contact request
        await newContactRequest.save();

        // Return a success response with the newly created contact request
        res.status(201).json({
            message: 'Contact request created successfully.',
            data: newContactRequest,
        });
    } catch (err) {
        // Log the error for debugging
        console.error('Error creating contact request:', err);

        // Handle different error types and provide specific HTTP status codes
        if (err.name === 'ValidationError' || err.name === 'CastError') {
            // Respond with a 400 Bad Request status for validation or casting errors
            res.status(400).json({ error: 'Invalid data provided: ' + err.message });
        } else {
            // Respond with a 500 Internal Server Error status for other errors
            res.status(500).json({ error: 'Failed to create contact request1: ' + err.message });
        }
    }
};


export async function getAllContactRequests(req, res) {
    try {
        // Find all contact requests and populate the user details
        const contactRequests = await ContactRequest.find()
            .populate('userId', 'name email phone') // Populate user details (name and email)

        // Return a success response with the list of contact requests
        res.status(200).json({
            message: 'Retrieved all contact requests successfully.',
            data: contactRequests,
        });
    } catch (err) {
        // Log the error for debugging
        console.error('Error retrieving contact requests:', err);

        // Respond with a 500 Internal Server Error status for other errors
        res.status(500).json({ error: 'Failed to retrieve contact requests: ' + err.message });
    }
}


export async function getContactRequestById(req, res) {
    try {
        // Extract the request ID from the route parameters
        const requestId = req.params.requestId;

        // Find the contact request by its ID
        const contactRequest = await ContactRequest.findById(requestId)
            .populate('userId', 'name email phone') // Populate user details (name and email)

        // Check if the contact request was found
        if (!contactRequest) {
            return res.status(404).json({ error: 'Contact request not found' });
        }

        // Return the retrieved contact request as a JSON response
        res.status(200).json({
            message: 'Contact request retrieved successfully.',
            data: contactRequest,
        });
    } catch (err) {
        // Log the error for debugging
        console.error('Error retrieving contact request:', err);

        // Respond with a 500 Internal Server Error status for other errors
        res.status(500).json({ error: 'Failed to retrieve contact request: ' + err.message });
    }
}




// Define the function to update the status of a contact request
export async function updateContactRequestStatus(req, res) {
    try {
        // Extract the request ID from the URL parameters
        const { requestId } = req.params;

        // Extract the new status from the request body
        const { status } = req.body;

        // Validate the new status value
        const validStatuses = ['complete', 'pending', 'rejected'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ error: 'Invalid status value' });
        }

        // Log the incoming request ID and status for debugging
        console.log('Request ID:', requestId);
        console.log('New status:', status);

        // Find the contact request by its ID and update its status
        const contactRequest = await ContactRequest.findByIdAndUpdate(
            requestId,
            { status },
            { new: true } // Return the updated document
        );

        // If the contact request was not found, return a 404 error
        if (!contactRequest) {
            return res.status(404).json({ error: 'Contact request not found' });
        }

        // Return a success response with the updated contact request
        res.json({
            message: 'Contact request status updated successfully.',
            data: contactRequest
        });
    } catch (err) {
        // Log the error for debugging
        console.error('Error updating contact request status:', err);

        // Return a 500 Internal Server Error response for other errors
        res.status(500).json({ error: 'Failed to update contact request status' });
    }
}
