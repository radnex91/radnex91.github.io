// Ergonomics layer: search/filter for the payload list and accessible names on
// the three fields that had none. Every entry point is guarded, so a failure
// here can never block the exploit flow.
(function () {
    'use strict';

    var BAR_ID = 'payloadSearchBar';
    var INPUT_ID = 'payloadSearchInput';
    var COUNT_ID = 'payloadSearchCount';
    var EMPTY_ID = 'payloadSearchEmpty';
    var DEBOUNCE_MS = 120;

    function norm(value) {
        var s = (value == null ? '' : String(value)).toLowerCase();
        try {
            s = s.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
        } catch (e) { /* normalize unsupported: compare as-is */ }
        return s;
    }

    function isHidden(el) {
        return /\bhidden\b/.test(el.className || '');
    }

    function activePanel() {
        var tab = document.querySelector('#default-tab [role="tab"][aria-selected="true"]');
        var target = tab ? tab.getAttribute('data-tabs-target') : null;
        if (target) {
            var panel = document.querySelector(target);
            if (panel && !isHidden(panel)) return panel;
        }
        var panels = document.querySelectorAll('#default-tab-content [role="tabpanel"]');
        for (var i = 0; i < panels.length; i++) {
            if (!isHidden(panels[i])) return panels[i];
        }
        return null;
    }

    function ensureLabels() {
        var fields = {
            ps4IpInput: 'PS4 IP address',
            ps4FwSelect: 'PS4 firmware version',
            customPayloadInput: 'Custom payload file, .bin or .elf'
        };
        for (var id in fields) {
            if (!Object.prototype.hasOwnProperty.call(fields, id)) continue;
            var el = document.getElementById(id);
            if (!el) continue;
            if (el.getAttribute('aria-label') || el.getAttribute('aria-labelledby')) continue;
            el.setAttribute('aria-label', fields[id]);
        }
    }

    function ensureSearchBar() {
        if (document.getElementById(BAR_ID)) return true;
        var host = document.getElementById('payloadsSection');
        if (!host) return false;
        var anchor = host.querySelector('.tabs') || document.getElementById('payloadsGrid');
        if (!anchor || !anchor.parentNode) return false;

        var bar = document.createElement('div');
        bar.id = BAR_ID;
        bar.className = 'payload-search';
        bar.setAttribute('role', 'search');

        var input = document.createElement('input');
        input.type = 'search';
        input.id = INPUT_ID;
        input.placeholder = 'Search payloads…';
        input.setAttribute('aria-label', 'Search payloads by name, author or description');
        input.setAttribute('autocomplete', 'off');
        input.setAttribute('spellcheck', 'false');

        var count = document.createElement('span');
        count.id = COUNT_ID;
        count.className = 'payload-search__count';
        count.setAttribute('aria-live', 'polite');
        count.hidden = true;

        var clear = document.createElement('button');
        clear.id = 'payloadSearchClear';
        clear.type = 'button';
        clear.className = 'payload-search__clear';
        clear.setAttribute('aria-label', 'Clear the payload search');
        clear.textContent = '\u2715';

        bar.appendChild(input);
        bar.appendChild(count);
        bar.appendChild(clear);

        var empty = document.createElement('p');
        empty.id = EMPTY_ID;
        empty.className = 'payload-search__empty';
        empty.textContent = 'No payload matches this search.';

        anchor.parentNode.insertBefore(bar, anchor);
        anchor.parentNode.insertBefore(empty, anchor);

        var timer = null;
        input.addEventListener('input', function () {
            if (timer) clearTimeout(timer);
            timer = setTimeout(applyFilter, DEBOUNCE_MS);
        });
        input.addEventListener('keydown', function (event) {
            if (event.key === 'Escape' || event.key === 'Esc') {
                input.value = '';
                applyFilter();
            }
        });
        clear.addEventListener('click', function () {
            input.value = '';
            applyFilter();
            try { input.focus(); } catch (e) { /* no-op */ }
        });

        return true;
    }

    function cardText(card) {
        return norm(card.textContent + ' ' + (card.getAttribute('data-payload-id') || ''));
    }

    function matches(card, query) {
        return !query || cardText(card).indexOf(query) !== -1;
    }

    // Only the visible tab strip is annotated: the counts tell you which tab
    // holds the matches, otherwise a per-tab filter looks like "no results".
    function updateTabBadges(query) {
        var tabs = document.querySelectorAll('#default-tab [role="tab"]');
        for (var i = 0; i < tabs.length; i++) {
            var tab = tabs[i];
            var target = tab.getAttribute('data-tabs-target');
            var panel = target ? document.querySelector(target) : null;
            var badge = tab.querySelector('.payload-search__badge');
            if (!query || !panel) {
                if (badge) badge.parentNode.removeChild(badge);
                continue;
            }
            var cards = panel.querySelectorAll('.payload-card');
            var found = 0;
            for (var j = 0; j < cards.length; j++) {
                if (matches(cards[j], query)) found++;
            }
            if (!found) {
                if (badge) badge.parentNode.removeChild(badge);
                continue;
            }
            if (!badge) {
                badge = document.createElement('span');
                badge.className = 'payload-search__badge';
                tab.appendChild(badge);
            }
            badge.textContent = found;
        }
    }

    function labelOf(panelId) {
        return panelId ? panelId.charAt(0).toUpperCase() + panelId.slice(1) : '';
    }

    function matchesElsewhere(query, ownPanel) {
        var panels = document.querySelectorAll('#default-tab-content [role="tabpanel"]');
        var total = 0, firstTab = '';
        for (var i = 0; i < panels.length; i++) {
            if (panels[i] === ownPanel) continue;
            var cards = panels[i].querySelectorAll('.payload-card');
            var found = 0;
            for (var j = 0; j < cards.length; j++) {
                if (matches(cards[j], query)) found++;
            }
            if (found) {
                total += found;
                if (!firstTab) firstTab = labelOf(panels[i].id);
            }
        }
        return { total: total, tab: firstTab };
    }

    function applyFilter() {
        var input = document.getElementById(INPUT_ID);
        var bar = document.getElementById(BAR_ID);
        var count = document.getElementById(COUNT_ID);
        var empty = document.getElementById(EMPTY_ID);
        if (!input || !bar) return;

        var scope = activePanel() || document.getElementById('default-tab-content');
        if (!scope) return;

        var isCustomTab = scope.id === 'custom';
        var query = norm(input.value.trim());

        // The custom tab holds no payload cards, so the search bar is useless there.
        bar.style.display = isCustomTab ? 'none' : '';

        var cards = scope.querySelectorAll('.payload-card');
        var shown = 0;
        for (var i = 0; i < cards.length; i++) {
            var match = matches(cards[i], query);
            cards[i].style.display = match ? '' : 'none';
            if (match) shown++;
        }

        if (count) {
            count.hidden = cards.length === 0;
            count.textContent = shown + '/' + cards.length;
        }
        bar.className = 'payload-search' + (query ? ' has-query' : '');

        updateTabBadges(query);

        if (empty) {
            var noneHere = query && cards.length > 0 && shown === 0;
            if (noneHere) {
                var elsewhere = matchesElsewhere(query, scope);
                empty.textContent = elsewhere.total
                    ? 'No match in this tab. ' + elsewhere.total + ' in ' + elsewhere.tab + '.'
                    : 'No payload matches this search.';
            }
            empty.className = 'payload-search__empty' + (noneHere ? ' is-visible' : '');
        }

        if (query) {
            var grid = document.getElementById('payloadsGrid');
            if (grid) grid.scrollTop = 0;
        }
    }

    function watchList() {
        var grid = document.getElementById('payloadsGrid');
        if (!grid || grid.__ergoWatched) return;
        if (typeof MutationObserver === 'undefined') return;
        grid.__ergoWatched = true;
        // Re-apply after renderPayloads() rebuilds a panel or saveLastTab()
        // empties the inactive ones. childList only: applyFilter() writes style,
        // so watching attributes would loop.
        var timer = null;
        var observer = new MutationObserver(function () {
            if (timer) clearTimeout(timer);
            timer = setTimeout(function () {
                ensureLabels();
                applyFilter();
            }, DEBOUNCE_MS);
        });
        observer.observe(grid, { childList: true, subtree: true });
    }

    function watchTabs() {
        var strip = document.getElementById('default-tab');
        if (!strip || strip.__ergoWatched) return;
        strip.__ergoWatched = true;
        strip.addEventListener('click', function () {
            setTimeout(applyFilter, 0);
        }, true);
    }

    function init() {
        try {
            if (!ensureSearchBar()) return;
            ensureLabels();
            watchList();
            watchTabs();
            applyFilter();
        } catch (e) {
            if (window.console && console.warn) console.warn('ergonomics: ' + e.message);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
    // Payloads arrive after an async fetch, and tabs render on first click.
    setTimeout(init, 1500);
    setTimeout(init, 4000);
})();
