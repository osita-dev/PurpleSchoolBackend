import mongoose from 'mongoose';

const MessageSchema = new mongoose.Schema({
  roomId: { type: mongoose.Schema.Types.ObjectId, ref: 'Room', required: true },
  userId: { type: String, required: true },
  username: { type: String },
  type: { type: String, enum: ['text', 'audio', 'system'], default: 'text' },
  content: { type: String }, // text or audio file URL
  moderation: {
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'approved' },
    reason: { type: String }
  },
  createdAt: { type: Date, default: Date.now }
});

// Export as ES Module
export default mongoose.model('Message', MessageSchema);
