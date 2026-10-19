<template><div>{{ name }}</div></template>
<script>
export default { mounted() { axios.get('/v1/profile/settings') } }
</script>
