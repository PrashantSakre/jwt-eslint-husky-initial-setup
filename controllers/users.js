const mongoose = require('mongoose')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const User = require('../models/users')

const connUri = process.env.MONGO_LOCAL_CONN_URL

module.exports = {
  add: (req, res) => {
    mongoose.connect(connUri, { useNewUrlParser: true }, mongoConErr => {
      const result = {}
      let status = 201
      if (!mongoConErr) {
        const { name, password } = req.body
        const user = new User({ name, password }) // document = instance of a model
        // TODO: We can hash the password here before we insert instead of in the model
        user.save((saveErr, newUser) => {
          if (!saveErr) {
            result.status = status
            result.result = newUser
          } else {
            status = 500
            result.status = status
            result.error = saveErr
          }
          res.status(status).send(result)
          // Close the connection after saving
          mongoose.connection.close()
        })
      } else {
        status = 500
        result.status = status
        result.error = mongoConErr
        res.status(status).send(result)

        mongoose.connection.close()
      }
    })
  },
  login: (req, res) => {
    const { name, password } = req.body

    mongoose.connect(connUri, { useNewUrlParser: true }, mongoConErr => {
      const result = {}
      let status = 200
      if (!mongoConErr) {
        User.findOne({ name }, (findOneErr, user) => {
          if (!findOneErr && user) {
            // We could compare passwords in our model instead of below as well
            bcrypt
              .compare(password, user.password)
              .then(match => {
                if (match) {
                  status = 200
                  // Create a token
                  const payload = { user: user.name }
                  const secret = process.env.JWT_SECRET
                  const token = jwt.sign(payload, secret)

                  // console.log('TOKEN', token);
                  result.token = token
                  result.status = status
                  result.result = user
                } else {
                  status = 401
                  result.status = status
                  result.error = 'Authentication error'
                }
                res.status(status).send(result)
              })
              .catch(err => {
                status = 500
                result.status = status
                result.error = err
                res.status(status).send(result)

                mongoose.connection.close()
              })
          } else {
            status = 404
            result.status = status
            result.error = findOneErr
            res.status(status).send(result)
          }
        })
          .clone()
          .catch(function (err) {
            console.log(err)
          })
          .then(() => mongoose.connection.close())
      } else {
        status = 500
        result.status = status
        result.error = mongoConErr
        res.status(status).send(result)

        mongoose.connection.close()
      }
    })
  },
  getAll: (req, res) => {
    mongoose.connect(
      connUri,
      { useNewUrlParser: true, useUnifiedTopology: true },
      mongoConErr => {
        const result = {}
        let status = 200
        if (!mongoConErr) {
          const payload = req.decoded
          // TODO: Log the payload here to verify that it's the same payload
          //  we used when we created the token
          console.log('PAYLOAD', payload)
          if (payload && payload.user === 'admin') {
            User.find({}, (findErr, users) => {
              if (!findErr) {
                result.status = status
                result.error = findErr
                result.result = users
              } else {
                status = 500
                result.status = status
                result.error = findErr
              }
              res.status(status).send(result)
            })
              .clone()
              .catch(function (err) {
                console.log(err)
              })
              .then(() => mongoose.connection.close())
          } else {
            status = 401
            result.status = status
            result.error = `Authentication error`
            res.status(status).send(result)

            mongoose.connection.close()
          }
        } else {
          status = 500
          result.status = status
          result.error = mongoConErr
          res.status(status).send(result)

          mongoose.connection.close()
        }
      }
    )
  },
}
