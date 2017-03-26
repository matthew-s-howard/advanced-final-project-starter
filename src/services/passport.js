import bcrypt from 'bcrypt';
import passport from 'passport';
import User from '../models/UserModel';
import {
  Strategy as JwtStrategy,
  ExtractJwt
} from 'passport-jwt';
import LocalStrategy from 'passport-local';

const signinStrategy = new LocalStrategy(function (username, password, done) {
  User.findOne(username).exec()
    .then(user => {
      // If there is no user found call done with a `null` argument, signifying no error
      // and `false` signifying that the signin failed
      if (!user) {
        return done(null, false);
      }

      bcrypt.compare(password, user.password, function (err, isMatch) {
        // If there is an error call done with our error
        if (err) {
          return done(err, false);
        }

        // If the passwords do not match call done with a `null` argument, signifying no error
        // and `false` signifying that the signin failed
        if (!isMatch) {
          return done(null, false);
        }

        // If we have no errors and the passwords match
        // call done with a `null` argument, signifying no error
        // and with the now signed in user
        return done(null, user);
      });
    })
    .catch(err => done(err, false));
});

// Tell passport to use this strategy
passport.use('signinStrategy', signinStrategy);

// Setup options for JwtStrategy
const jwtOptions = {
  // Get the secret from our environment
  secretOrKey: process.env.SECRET,
  // Tell our strategy where to find our token in the request
  jwtFromRequest: ExtractJwt.fromHeader('authorization')
};

// Create JWT strategy
// This will take our token and decode it to
// extract the information we have stored in it
const authStrategy = new JwtStrategy(jwtOptions, function (payload, done) {
  User.findById(payload.userId, function (err, user) {
    if (err) { return done(err, false); }

    if (user) {
      done(null, user);
    } else {
      done(null, false);
    }
  });
});

// Tell passport to use this strategy
passport.use('authStrategy', authStrategy);
passport.use('signinStrategy', signinStrategy);
