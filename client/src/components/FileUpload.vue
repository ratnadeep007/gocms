<template>
  <div class="hello">
    <form enctype="multipart/form-data" novalidate v-if="isInitial || isSaving">
      <h1>Upload images</h1>
      <div class="dropbox">
        <input type="file" multiple :name="uploadFieldName" :disabled="isSaving" @change="filesChange($event.target.name, $event.target.files); fileCount = $event.target.files.length"
          accept="image/*" class="input-file">
          <p v-if="isInitial">
            Drag your file(s) here to begin<br> or click to browse
          </p>
          <p v-if="isSaving">
            Uploading {{ fileCount }} files...
          </p>
      </div>
    </form>
  </div>
</template>

<script>
import * as axios from 'axios';

const STATUS_INITIAL = 0, STATUS_SAVING = 1, STATUS_SUCCESS = 2, STATUS_FAILED = 3;

export default {
  name: 'FileUpload',
  props: {
    msg: String
  },

  data() {
    return {
      uploadedFiles: [],
      uploadError: null,
      currentStatus: null,
      uploadFieldName: 'photos'
    }
  },
  computed: {
    isInitial() {
      return this.currentStatus === STATUS_INITIAL;
    },
    isSaving() {
      return this.currentStatus === STATUS_SAVING;
    },
    isSuccess() {
      return this.currentStatus === STATUS_SUCCESS;
    },
    isFailed() {
      return this.currentStatus === STATUS_FAILED;
    }
  },
  methods: {
    reset() {
      // reset form to initial state
      this.currentStatus = STATUS_INITIAL;
      this.uploadedFiles = [];
      this.uploadError = null;
    },
    save(formData) {
      // upload data to the server
      this.currentStatus = STATUS_SAVING;
      console.log(formData)
      let auth = localStorage.getItem('cms-auth');
      axios.post('http://localhost:8080/file', formData, { headers: { Authorization: auth }})
        .then(res => console.log(res['data']))
    },
    filesChange(fieldName, fileList) {
      // handle file changes
      const formData = new FormData();
      console.log(fieldName, fileList)
      if (!fileList.length) return;

        // append the files to FormData
        Array
          .from(Array(fileList.length).keys())
          .map(x => {
            formData.append('file', fileList[x], fileList[x].name);
          });
        console.log(formData.get('photos'))

        // save it
        this.save(formData);
      }
    },
    mounted() {
      this.reset();
    },
  }
</script>