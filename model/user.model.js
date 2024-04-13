import mongoose from "mongoose";

export const UserSchema = new mongoose.Schema({
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
    isemailverify: {
        type: Boolean,
        default: false
    },
    verifyOTP: {
        type: String,
        default: " "
    },
    OTPtimeperiod: {
        type: String,
        default: " "
    },
    resetToken: {
        type: String,
        default: ""
    },
    tokenperiod: {
        type: String,
        default: " "
    }

});

export default mongoose.model.Users || mongoose.model('User', UserSchema);