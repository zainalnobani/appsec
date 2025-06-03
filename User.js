const mongoose = require('mongoose');
const userSchema = new mongoose.Schema({
    name: { type: String, required: true, minlength: 2, maxlength: 30 },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' }
});

module.exports = mongoose.model('User', userSchema);
