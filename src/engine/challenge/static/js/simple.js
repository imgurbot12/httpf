const challenge = eval("{{ cookie_value }}");
document.cookie = `{{ cookie_name }}=${challenge}; Path=/;`;
setTimeout(() => location.reload(), 1000);
