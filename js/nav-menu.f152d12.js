/* Versioned with the unified-header deployment to prevent HTML/CSS/JS cache skew. */
(function () {
  'use strict';

  var toggle = document.querySelector('[data-nav-toggle]');
  var navigation = document.querySelector('[data-nav-menu]');
  if (!toggle || !navigation) return;

  var label = toggle.querySelector('.nav-toggle-label');

  function setLabel(open) {
    if (!label) return;
    label.textContent = open ? 'Close wallet navigation' : 'Open wallet navigation';
  }

  function closeNavigation(returnFocus) {
    toggle.setAttribute('aria-expanded', 'false');
    navigation.removeAttribute('data-open');
    setLabel(false);
    if (returnFocus) toggle.focus();
  }

  toggle.addEventListener('click', function () {
    var open = toggle.getAttribute('aria-expanded') !== 'true';
    toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    navigation.toggleAttribute('data-open', open);
    setLabel(open);
  });

  navigation.addEventListener('click', function (event) {
    if (event.target.closest('a') && window.matchMedia('(max-width: 1200px)').matches) {
      closeNavigation(false);
    }
  });

  window.addEventListener('resize', function () {
    if (window.matchMedia('(min-width: 1201px)').matches) closeNavigation(false);
  });

  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape' && toggle.getAttribute('aria-expanded') === 'true') {
      closeNavigation(true);
    }
  });
}());
