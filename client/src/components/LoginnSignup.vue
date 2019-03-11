<template>
  <div class="hello">
    <form enctype="application/json">
      <h1>Upload images</h1>
      <div v-if="!loading" class="dropbox">
        <div v-if="error">{{error}}</div>
        <input type="text" v-model="username">
        <input type="password" v-model="password">
        <input type="button" value="Login" @click="login">
      </div>
      <div v-if="loading">Loading...</div>
    </form>
  </div>
</template>

<script>
// import { login } from './login-signup.service';
import * as axios from 'axios';

export default {
  name: 'LoginnSignup',
  props: {
    msg: String
  },

  data() {
    return {
      username: null,
      password: null,
      error: null,
      loading: false
    }
  },
  methods: {
    login() {
      if (!this.validate()) {
        return;
      }
      this.loading = true;
      const loginData = {
        username: this.username,
        password: this.password
      };
      axios.post('http://localhost:8080/user', loginData)
        .then(res => res['data'])
        .then(res => {
          console.log(res);
          localStorage.setItem('cms-auth', 'GOCMS '+res['Token'])
          this.loading = false;
        })
    },
    validate() {
      console.log('in validate')
      if (this.username < 3 || this.username > 15) {
        this.error = 'Username must be between 5 and 15 characters long';
        return false;
      }
      if (this.password < 6) {
        this.error = 'Pass must be greater than 6 characters long';
        return false;
      }
      return true;
    }
  }
}
</script>