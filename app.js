(() => {
  const sidebar = document.getElementById('sidebar');
  const toggle = document.getElementById('sidebarToggle');
  if (sidebar && toggle) {
    toggle.addEventListener('click', () => {
      sidebar.classList.toggle('sidebar-open');
      document.body.classList.toggle('sidebar-visible');
    });
    document.addEventListener('click', event => {
      if (window.innerWidth < 992 && sidebar.classList.contains('sidebar-open')
          && !sidebar.contains(event.target) && !toggle.contains(event.target)) {
        sidebar.classList.remove('sidebar-open');
        document.body.classList.remove('sidebar-visible');
      }
    });
  }
  document.querySelectorAll('[data-confirm]').forEach(el => {
    el.addEventListener('click', event => {
      if (!window.confirm(el.getAttribute('data-confirm'))) event.preventDefault();
    });
  });
})();
