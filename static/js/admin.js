// 管理后台通用脚本
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

  // 移动端侧边栏切换
  const sidebarToggle = document.querySelector(".navbar-toggler")
  if (sidebarToggle) {
    sidebarToggle.addEventListener("click", () => {
      document.querySelector(".sidebar").classList.toggle("show")
    })
  }

  // 表格行悬停效果
  const tableRows = document.querySelectorAll("tbody tr")
  tableRows.forEach((row) => {
    row.addEventListener("mouseover", () => {
      row.classList.add("table-hover")
    })
    row.addEventListener("mouseout", () => {
      row.classList.remove("table-hover")
    })
  })

  // 模态框关闭后重置表单
  const modals = document.querySelectorAll(".modal")
  modals.forEach((modal) => {
    modal.addEventListener("hidden.bs.modal", () => {
      const form = modal.querySelector("form")
      if (form) {
        form.reset()
      }
    })
  })

  // 确认删除操作
  const confirmDeleteButtons = document.querySelectorAll("[data-confirm]")
  confirmDeleteButtons.forEach((button) => {
    button.addEventListener("click", (e) => {
      if (!confirm(button.dataset.confirm)) {
        e.preventDefault()
      }
    })
  })
})

