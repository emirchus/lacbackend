const mongoose = require('mongoose');

var playerDataSchema = new mongoose.Schema({
    uuid: {
        type: String,
        unique: true,
        required: true,
        trim: true
    },
    recentName: {
        type: String,
        unique: true,
        required: true,
        trim: true
    },
    recentNameLowercase: {
        type: String,
        unique: true,
        required: true,
        trim: true
    },
    recentNameLength: {
        type: Number,
        unique: true,
        required: true,
        trim: true
    },
    last_login: {
        type: Number,
        unique: true,
        required: true,
        trim: true
    },
    last_address: {
        type: String,
        unique: true,
        required: true,
        trim: true
    },
    punishments: {
        type: Array,
        unique: true,
        required: true,
        trim: true
    },
    social: {
        status: {type: String},
        friends: [{
            type : String
        }],
        requests: [String]
    },
    cape: {
        type: String
    },
    skin: {
        type: String
    }
    
}, {collection: 'playerData'});
var playerData = mongoose.model('playerData', playerDataSchema);

module.exports = playerData;