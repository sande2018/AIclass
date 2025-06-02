// 页面加载完成后执行
document.addEventListener("DOMContentLoaded", () => {
  // 自动关闭警告消息
  const alerts = document.querySelectorAll(".alert")
  alerts.forEach((alert) => {
    setTimeout(() => {
      const closeButton = alert.querySelector(".btn-close")
      if (closeButton) {
        closeButton.click()
      }
    }, 5000)
  })

  // 添加平滑滚动效果
  document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
    anchor.addEventListener("click", function (e) {
      e.preventDefault()
      const targetId = this.getAttribute("href")
      if (targetId !== "#") {
        const targetElement = document.querySelector(targetId)
        if (targetElement) {
          targetElement.scrollIntoView({
            behavior: "smooth",
          })
        }
      }
    })
  })

  // 为移动设备添加触摸支持
  const isTouchDevice = "ontouchstart" in window || navigator.maxTouchPoints > 0
  if (isTouchDevice) {
    document.body.classList.add("touch-device")
  }

  // 响应式导航栏处理
  const navbarToggler = document.querySelector(".navbar-toggler")
  if (navbarToggler) {
    navbarToggler.addEventListener("click", () => {
      document.body.classList.toggle("navbar-open")
    })
  }

  // 密码可见性切换
  const passwordInputs = document.querySelectorAll('input[type="password"]')
  passwordInputs.forEach((input) => {
    const wrapper = document.createElement("div")
    wrapper.className = "password-wrapper position-relative"
    input.parentNode.insertBefore(wrapper, input)
    wrapper.appendChild(input)

    const toggleButton = document.createElement("button")
    toggleButton.type = "button"
    toggleButton.className = "btn btn-sm position-absolute end-0 top-50 translate-middle-y bg-transparent border-0"
    toggleButton.innerHTML = '<i class="bi bi-eye"></i>'
    toggleButton.style.zIndex = "10"
    wrapper.appendChild(toggleButton)

    toggleButton.addEventListener("click", function () {
      if (input.type === "password") {
        input.type = "text"
        this.innerHTML = '<i class="bi bi-eye-slash"></i>'
      } else {
        input.type = "password"
        this.innerHTML = '<i class="bi bi-eye"></i>'
      }
    })
  })
})

