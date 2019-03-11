<template>
  <div class="home">
    <FileUpload msg="Welcome to Your Vue.js App"/>
    <LoginnSignup></LoginnSignup>
    <Files v-if="isLoggedIn"></Files>
  </div>
</template>

<script>
// @ is an alias to /src
import FileUpload from '@/components/FileUpload.vue'
import LoginnSignup from '@/components/LoginnSignup.vue'
import Files from '@/components/Files.vue'

export default {
  name: 'home',
  components: {
    FileUpload,
    LoginnSignup,
    Files
  },
  data() {
    return {
      isLoggedIn: false
    }
  },
  mounted() {
    if(localStorage.getItem('cms-auth')) {
      this.isLoggedIn = true;
    }
  }
}
</script>
