const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const mailer = require('../Utilities/SendgridMailer')
const User = require('../../models/UserModel')
const { registerValidator, loginValidator, updateValidator } = require('./Validator')

var UserController = {
    login: async(req, res) => {
        try{
            await loginValidator(req.body)

            const user = (req.body.email == null) ? await User.findOne({username: req.body.username}) :
                await user.findOne({email: req.body.email})

            // Valores almacenados en user
            // Objeto de tipo user / Null
            if(!user)
                throw {error: true, message: "Username or Email not found"}

            var logged = await bcrypt.compare(req.body.password, user.password)

            if(!logged)
                throw {error: true, message: "Wrong password"}

            const token = jwt.sign({_id: user._id}, process.env.TOKEN_KEY)

            return res.status(200).json({token: token})
        }
        catch(err){
            return res.status(400).json(err.details != null ? err.details[0].message : err)
        }
    },

    register: async(req, res) => {
        try{
            await registerValidator(req.body)

            /*
                MongoDB
                SELECT * FROM USERS WHERE user.email = requ.body.email OR user.username = req.body.username
            */
           const notUnique = await User.find({ $or: [{username: req.body.username}, {email: req.body.email}] })

           if(notUnique.length != 0)
                throw "Email or username already registered"

            let hashedPassword = await bcrypt.hash(req.body.password, parseInt(process.env.SALT))

            let newUser = new User({
                fullname: req.body.fullname,
                username: req.body.username,
                email: req.body.email,
                password: hashedPassword,
                phone: req.body.phone,
                dob: req.body.dob,
                profileImg: req.file.location
            })

            await newUser.save()
            return res.status(201).json({ error: "false", message: "Created" })
        }
        catch(err){
            return res.status(400).json(err.details != null ? err.details[0].message : err)
        }

        /*
        let newUser = new User({
            fullname: req.body.fullname,
            username: req.body.username,
            email: req.body.email,
            password: req.body.password,
            phone: req.body.phone,
            dob: req.body.dob
        })

        await newUser.save()

        return res.status(201).json({ error: "false", message: "Created" })
        */
    },

    updateUser: async(req, res) => {
        try{
            await updateValidator(req.body)

            var actualUser = await User.findOne({_id: req.user._id})
            const matchUsers = await User.find({ $or: [{username: req.body.username}, {email: req.body.email}] })

            var unique = true

            if(matchUsers.length != 0)
                matchUsers.forEach(u => {
                    if(req.user._id != u._id)
                        if(u.username == req.body.username || u.email == req.body.email)
                            unique = false
                })
            
            if(!unique)
                throw {error: true, message: "Email or username already registered"}

            var hashedPassword = req.body.password == null ? null :
                await bcrypt.hash(req.body.password, parseInt(process.env.SALT))

            actualUser = {
                fullname: req.body.fullname || actualUser.name,
                username: req.body.username || actualUser.username,
                email: req.body.email || actualUser.email,
                phone: req.body.phone || actualUser.phone,
                dob: req.body.dob || actualUser.dob,
                password: hashedPassword || actualUser.password
            }

            await User.findOneAndUpdate({_id: req.user._id}, actualUser)
            return res.status(200).json({error: false, message: "Updated"})
        }
        catch(err){
            console.log(err);
            return res.status(400).json(err.details != null ? err.details[0].message : err)
        }
    },

    requestPassword: async(req, res) => {
        try{
            var user = await User.findOne({email: req.body.email})

            if(!user)
                throw {error: true, message: "Email not found"}

            /*
                Se recibe una request con el email del usuario
                Se encuentra el usuario

                Crear un token de recuperacion (token para resetear contraseña / TOKEN_RESET_KEY)
                Se concatena la URL base de la API con el token **
                Guardar el token en los datos del usuario (recoveryLink / recoveryToken)

                Se genera la nueva URL **
                Se envia el correo con la nueva URL
            */

            /*
                Verificar el req.jeades -> token enviado es un Authorize temporal
                Buscar el usuario con el recoveryLink / token
                Encriptar la nueva password
                Actualizar datos del usuario
                Solicitarle al usuario que se vuelva a loggear
            */

            const token = jwt.sign({_id: user._id}, process.env.TOKEN_RESET_KEY, {expiresIn: '15m'})
            const recoverEmail = {
                to: req.body.email,
                from: process.env.MAIL,
                subject: "CursoBack: Recuperación de contraseña",
                html: 
                `

                <h2>Saludos ${user.fullname}</h2>
                <p>Para que puedas recuperar tu contraseña es necesario que visites el siguiente enlace:</p>
                <a href="${process.env.CLIENT_URL}/auth/${token}" target="_blank">Recuperación</a>
                <p>Si necesitas ayuda puedes escribir a: ${process.env.DEVELOPER_EMAIL}</p>

                `
            }

            await User.findOneAndUpdate({_id: user._id}, {recoveryToken: token})
            await mailer(recoverEmail)
            return res.header('Authorize', token).status(200).json({error: false, message: "Email sent"})
        }
        catch(err){
            console.log(err);
            return res.status(500).json(err)
        }
    },

    // Body: nueva contraseña
    // Headers: Content Type: aplication, Authorize: token
    requestPasswordHandler: async(req, res) => {
        try {
            const token = req.header('Authorize')

            if(!token)
                throw {error: true, message: "Access denied"}

            const verified = jwt.verify(token, process.env.TOKEN_RESET_KEY)

            if(!verified)
                throw {error: true, message: "Invalid token"}
            
            var user = await User.findOne({_id: verified._id})

            user.password = await bcrypt.hash(req.body.newPassword, parseInt(process.env.SALT))
            user.recoveryToken = null

            await User.findOneAndUpdate({_id: user._id}, {password: user.password, recoveryToken: user.recoveryToken})

            return res.status(200).json({error: false, message: "Updated password, try login in"})
        }
        catch(err) {
            console.log(err);
            return res.status(500).json(err)
        }
    },

    getUsers: async(req, res) => {
        try{
            const { page = 1, limit = 3 } = req.query

            const users = await User.find()
                .limit(limit * 1)
                .skip((page - 1) * limit)
                .exec()

            const count = await User.countDocuments()

            /*
            Retornar:
                Pagina actual
                Elementos existentes
                Elementos
            */

            return res.status(200).json({
                totalPages: Math.ceil(count / limit),
                currentPage: page,
                users
            })            
        }
        catch(err){
            console.log(err);
            return res.status(500).json({error: true, message: "Something went wrong"})
        }
    },

    getCurrentUser: async(req, res) => {
        const user = await User.findOne({_id: req.user._id})

        return res.status(200).json(user)
    }
}

module.exports = UserController