import React, { Component } from 'react';
import { BrowserRouter, Route, Switch } from 'react-router-dom';
import axios from 'axios';
import './App.css';
import SignUpSignIn from './SignUpSignIn';
import TopNavbar from './TopNavbar';
import Secret from './Secret';

class App extends Component {
  constructor() {
    super();

    this.state = {
      signUpSignInError: '',
      authenticated: localStorage.getItem('token') || false
    };
  }

  handleSignUp(credentials) {
    const { username, password, confirmPassword } = credentials;
    if (!username.trim() || !password.trim() || password.trim() !== confirmPassword.trim()) {
      this.setState({
        signUpSignInError: 'Must Provide All Fields'
      });
    } else {
      axios.post('/api/signup', credentials)
        .then(resp => {
          const { token } = resp.data;
          localStorage.setItem('token', token);

          this.setState({
            signUpSignInError: '',
            authenticated: token
          });
        });
    }
  }

  handleSignIn(credentials) {
    // Handle Sign Up
  }

  handleSignOut() {
    localStorage.removeItem('token');
    this.setState({
      authenticated: false
    });
  }

  renderSignUpSignIn() {
    return (
      <SignUpSignIn
        error={this.state.signUpSignInError}
        onSignUp={this.handleSignUp.bind(this)} />
    );
  }

  renderApp() {
    return (
      <div>
        <Switch>
          <Route exact path="/" render={() => <h1>I am protected!</h1>} />
          <Route exact path="/secret" component={Secret} />
          <Route render={() => <h1>NOT FOUND!</h1>} />
        </Switch>
      </div>
    );
  }

  render() {
    return (
      <BrowserRouter>
        <div className="App">
          <TopNavbar
            showNavItems={this.state.authenticated}
            onSignOut={this.handleSignOut.bind(this)} />
          {this.state.authenticated ? this.renderApp() : this.renderSignUpSignIn()}
        </div>
      </BrowserRouter>
    );
  }
}

export default App;
