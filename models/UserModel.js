const { Schema, model } = require('mongoose')

var UserSchema = Schema({
    fullname: {
        type: "String",
        required: true
    },
    username: {
        type: "String",
        required: true,
        unique: true,
        min: 6
    },
    email: {
        type: "String",
        required: true,
        unique: true,
    },
    password: {
        type: "String",
        required: true
    },
    phone: "String",
    // Date of birth
    dob: "Date",
    recoveryToken: "String",
    profileImg: "String"
})

module.exports = model("User", UserSchema)