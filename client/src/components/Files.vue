<template>
  <div>
    <input type="text" v-model="url"> <input type="button" value="Download" @click="downloadFile">
    <div v-for="file in files" v-bind:key="file.ID">
      <img width="400" height="600" :src="file.MinioLink.replace('https://', 'http://')">
    </div>
  </div>
</template>

<script>
import * as axios from 'axios'

export default {
  name: 'Files',
  data() {
    return {
      files: [],
      url: null
    }
  },
  methods: {
    getAllFiles() {
      let auth = localStorage.getItem('cms-auth');
      console.log(auth);
      axios.get('http://localhost:8080/files', { headers: { Authorization: auth}})
        .then(res => {
          console.log(res['data']);
          this.files = res['data'];
        })
    },
    downloadFile() {
      let auth = localStorage.getItem('cms-auth');
      axios.post('http://localhost:8080/file/downloadext', { url: this.url}, { headers: { Authorization: auth}})
        .then(res => res['data'])
        .then(res => console.log(res));
    }
  },
  mounted() {
    this.getAllFiles()
  }
}
</script>
