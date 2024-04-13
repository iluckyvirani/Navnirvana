// userComment.model.js

import mongoose from 'mongoose';

const userCommentSchema = new mongoose.Schema({
    customerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Reference to the User model
    comment: { type: String, required: true },
    selectedService: { type: String, required: true }
});

const UserComment = mongoose.model('UserComment', userCommentSchema);

export default UserComment;
