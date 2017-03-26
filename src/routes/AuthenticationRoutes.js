import express from 'express';
const router = express.Router();
import jwt from 'jwt-simple';
import User from '../models/UserModel';
import bcrypt from 'bcrypt';
import passport from 'passport';

// Require our custom strategies
require('../services/passport');

const signinStrategy = passport.authenticate('signinStrategy', { session: false });

// Helper method to create a token for a user
function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ userId: user.id, iat: timestamp }, 'abc123');
}

router.post('/api/signin', signinStrategy, function (req, res, next) {
  res.json({ token: tokenForUser(req.user)});
});

router.post('/api/signup', function (req, res, next) {
  console.log('did we fire?');
  // Grab the username and password from our request body
  const { username, password } = req.body;

  // If no username or password was supplied return an error
  if (!username || !password) {
    return res.status(422)
      .json({ error: 'You must provide an username and password' });
  }

  // Look for a user with the current user name
  User.findOne({ username }).exec()
    .then((existingUser) => {
      // If the user exist return an error on sign up
      if (existingUser) {
        return res.status(422).json({ error: 'Username is in use' });
      }

      // If the user does not exist create the user
      // User bcrypt to has their password, remember, we never save plain text passwords!
      bcrypt.hash(password, 10, function (err, hashedPassword) {
        if (err) {
          return next(err);
        }

        // Create a new user with the supplied username, and the hashed password
        const user = new User({ username, password: hashedPassword });

        // Save and return the user
        user.save()
          .then(newUser => res.json({ token: tokenForUser(newUser) }));
      });
    })
    .catch(err => next(err));
});

module.exports = router;
