import mongoose from 'mongoose';

const serviceOptions = ['general', 'insurance', 'loans', 'credit cards', 'investments', 'mutual funds'];

const commentSchema = new mongoose.Schema({
    comment:
    {
        type: String,
        required: true
    },
    selectedService:
    {
        type: String,
        required: true,
        enum: serviceOptions
    },
    timestamp:
    {
        type: Date,
        default: Date.now
    }
});

const Comment = mongoose.model('Comment', commentSchema);

export default Comment;




