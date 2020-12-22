const jwt = require('jsonwebtoken')

function Authenticate(req, res, next) {
    const token = req.header('Authorize')

    if(!token)
        return res.status(401).json({error: true, message: "Access Denied"})

    try{
        // Verificacion y desemcriptacion
        const verified = jwt.verify(token, process.env.TOKEN_KEY)
        req.user = verified
        next()
    }
    catch(err){
        return res.status(400).json({error: true, message: "Invalid token"})
    }
}

module.exports = Authenticate