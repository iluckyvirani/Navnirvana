import mongoose from 'mongoose';

const contactRequestSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        // required: true,
        index: true // Index for faster lookups
    },
    category: {
        type: String,
        enum: ['general', 'insurance', 'loans','credit_cards', 'investments','mutual_funds' ],
        required: true
    },
    comment: {
        type: String,
        required: true,
        maxlength: 500 // Optional: Limit comment length
    },
    status: {
        type: String,
        enum: ['complete', 'pending', 'rejected'],
        default: 'pending', // Default to 'pending'
        required: true
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
    
}, {
    timestamps: true // Automatically manage createdAt and updatedAt
});


export default mongoose.models.ContactRequest || mongoose.model('ContactRequest', contactRequestSchema);
