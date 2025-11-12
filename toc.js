// Populate the sidebar
//
// This is a script, and not included directly in the page, to control the total size of the book.
// The TOC contains an entry for each page, so if each page includes a copy of the TOC,
// the total size of the page becomes O(n**2).
class MDBookSidebarScrollbox extends HTMLElement {
    constructor() {
        super();
    }
    connectedCallback() {
        this.innerHTML = '<ol class="chapter"><li class="chapter-item expanded "><a href="whatis.html"><strong aria-hidden="true">1.</strong> What is ClairV4</a></li><li class="chapter-item expanded "><a href="howto.html"><strong aria-hidden="true">2.</strong> How Tos</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="howto/getting_started.html"><strong aria-hidden="true">2.1.</strong> Getting Started With ClairV4</a></li><li class="chapter-item expanded "><a href="howto/deployment.html"><strong aria-hidden="true">2.2.</strong> Deployment Models</a></li><li class="chapter-item expanded "><a href="howto/api.html"><strong aria-hidden="true">2.3.</strong> API Definition</a></li><li class="chapter-item expanded "><a href="howto/testing.html"><strong aria-hidden="true">2.4.</strong> Testing ClairV4</a></li></ol></li><li class="chapter-item expanded "><a href="concepts.html"><strong aria-hidden="true">3.</strong> Concepts</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="concepts/indexing.html"><strong aria-hidden="true">3.1.</strong> Indexing</a></li><li class="chapter-item expanded "><a href="concepts/matching.html"><strong aria-hidden="true">3.2.</strong> Matching</a></li><li class="chapter-item expanded "><a href="concepts/api_internal.html"><strong aria-hidden="true">3.3.</strong> Internal API</a></li><li class="chapter-item expanded "><a href="concepts/authentication.html"><strong aria-hidden="true">3.4.</strong> Authentication</a></li><li class="chapter-item expanded "><a href="concepts/notifications.html"><strong aria-hidden="true">3.5.</strong> Notifications</a></li><li class="chapter-item expanded "><a href="concepts/updatersandairgap.html"><strong aria-hidden="true">3.6.</strong> Updaters and Airgap</a></li><li class="chapter-item expanded "><a href="concepts/operation.html"><strong aria-hidden="true">3.7.</strong> Operation</a></li></ol></li><li class="chapter-item expanded "><a href="contribution.html"><strong aria-hidden="true">4.</strong> Contribution</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="contribution/building.html"><strong aria-hidden="true">4.1.</strong> Building</a></li><li class="chapter-item expanded "><a href="contribution/commit_style.html"><strong aria-hidden="true">4.2.</strong> Commit Style</a></li><li class="chapter-item expanded "><a href="contribution/releases.html"><strong aria-hidden="true">4.3.</strong> Releases</a></li><li class="chapter-item expanded "><a href="contribution/openapi.html"><strong aria-hidden="true">4.4.</strong> OpenAPI</a></li></ol></li><li class="chapter-item expanded "><a href="reference.html"><strong aria-hidden="true">5.</strong> Reference</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="reference/api.html"><strong aria-hidden="true">5.1.</strong> Api</a></li><li class="chapter-item expanded "><a href="reference/clairctl.html"><strong aria-hidden="true">5.2.</strong> Clairctl</a></li><li class="chapter-item expanded "><a href="reference/config.html"><strong aria-hidden="true">5.3.</strong> Config</a></li><li class="chapter-item expanded "><a href="reference/indexer.html"><strong aria-hidden="true">5.4.</strong> Indexer</a></li><li class="chapter-item expanded "><a href="reference/matcher.html"><strong aria-hidden="true">5.5.</strong> Matcher</a></li><li class="chapter-item expanded "><a href="reference/notifier.html"><strong aria-hidden="true">5.6.</strong> Notifier</a></li><li class="chapter-item expanded "><a href="reference/metrics.html"><strong aria-hidden="true">5.7.</strong> Metrics</a></li></ol></li></ol>';
        // Set the current, active page, and reveal it if it's hidden
        let current_page = document.location.href.toString().split("#")[0].split("?")[0];
        if (current_page.endsWith("/")) {
            current_page += "index.html";
        }
        var links = Array.prototype.slice.call(this.querySelectorAll("a"));
        var l = links.length;
        for (var i = 0; i < l; ++i) {
            var link = links[i];
            var href = link.getAttribute("href");
            if (href && !href.startsWith("#") && !/^(?:[a-z+]+:)?\/\//.test(href)) {
                link.href = path_to_root + href;
            }
            // The "index" page is supposed to alias the first chapter in the book.
            if (link.href === current_page || (i === 0 && path_to_root === "" && current_page.endsWith("/index.html"))) {
                link.classList.add("active");
                var parent = link.parentElement;
                if (parent && parent.classList.contains("chapter-item")) {
                    parent.classList.add("expanded");
                }
                while (parent) {
                    if (parent.tagName === "LI" && parent.previousElementSibling) {
                        if (parent.previousElementSibling.classList.contains("chapter-item")) {
                            parent.previousElementSibling.classList.add("expanded");
                        }
                    }
                    parent = parent.parentElement;
                }
            }
        }
        // Track and set sidebar scroll position
        this.addEventListener('click', function(e) {
            if (e.target.tagName === 'A') {
                sessionStorage.setItem('sidebar-scroll', this.scrollTop);
            }
        }, { passive: true });
        var sidebarScrollTop = sessionStorage.getItem('sidebar-scroll');
        sessionStorage.removeItem('sidebar-scroll');
        if (sidebarScrollTop) {
            // preserve sidebar scroll position when navigating via links within sidebar
            this.scrollTop = sidebarScrollTop;
        } else {
            // scroll sidebar to current active section when navigating via "next/previous chapter" buttons
            var activeSection = document.querySelector('#sidebar .active');
            if (activeSection) {
                activeSection.scrollIntoView({ block: 'center' });
            }
        }
        // Toggle buttons
        var sidebarAnchorToggles = document.querySelectorAll('#sidebar a.toggle');
        function toggleSection(ev) {
            ev.currentTarget.parentElement.classList.toggle('expanded');
        }
        Array.from(sidebarAnchorToggles).forEach(function (el) {
            el.addEventListener('click', toggleSection);
        });
    }
}
window.customElements.define("mdbook-sidebar-scrollbox", MDBookSidebarScrollbox);
