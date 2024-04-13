import mongoose from "mongoose";

export const AdminSchema = new mongoose.Schema({
    name: {
        type: String,
    },
    phone: {
        type: Number,
        required: [true, "Please provide a unique phone no."],
        unique: true,
    },
    email: {
        type: String,
        required: [true, "Please provide a unique email"],
        unique: true,
    },
    password: {
        type: String,
        required: [true, "Please provide a password"],
        unique: false,
    },
    role: {
        type: String,
        enum: ['superadmin', 'admin'], // Restrict values to 'superadmin' or 'admin'
        default: 'admin' // Default role is 'admin'
    }
});

export default mongoose.model.Admin || mongoose.model('Admin', AdminSchema);
