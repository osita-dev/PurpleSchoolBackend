import mongoose from 'mongoose';

const RoomSchema = new mongoose.Schema({
  title: { type: String, required: true },
  subject: { type: String, default: '' },
  createdBy: { type: String, required: true }, // userId or username
  members: [
    {
      userId: String,
      username: String,
      joinedAt: { type: Date, default: Date.now }
    }
  ],
  expiresAt: { type: Date }, // optional
  createdAt: { type: Date, default: Date.now }
});

// Export as ES Module
export default mongoose.model('Room', RoomSchema);
