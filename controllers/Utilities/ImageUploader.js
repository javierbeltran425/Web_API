const aws = require('aws'), multer = require('multer'), multerS3 = require('multer-s3')

aws.config.update({
    secretAccesKey: process.env.AWS_KEY,
    secretKeyId: process.env.AWS_KEY_ID,
    region: 'us-east-1'
})

const s3 = new aws.S3()

module.exports = {
    upload: multer({
        storage: multerS3({
            s3: s3,
            acl: 'public-read',
            bucket: process.env.AWS_BUCKET,
            key: function(req, file, cb) {
                cb(null, 'profileImg/' + new Date().toISOString() + '_' + file.originalname)
            }
        })
    }),
    limits: {
        fileSize: 1024 * 1024 * 5
    }
}