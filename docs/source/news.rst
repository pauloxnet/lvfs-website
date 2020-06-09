LVFS Releases
#############

1.2.0 (2020-06-09)
==================

This release adds the following features:

* Add a filter view for user uploaded firmware
* Add a plugin to identify old microcode versions
* Add cached public stats of useful metrics
* Add support for LVFS::UpdateMessage
* Allow clients to upload anonymous HSI attrs
* Allow re-signing binaries
* Create Jcat files in archives and for metadata
* Delete firmware in embargo with newer public versions
* Disable unused user accounts for GDPR compliance
* Export the success confidence to the mdsync vendor
* Include LVFS::UpdateProtocol in the metadata
* Rewrite the AppStream screenshot URL to use the server CDN
* Rewrite the metainfo when signing the firmware
* Save metadata about Intel microcode blobs
* Support Lenovo, Dell and Intel specific security tags
* Use celery to process async operations

This release fixes the following bugs:

* Allow all users to view the profile page
* Allow a protocol to have no defined version format
* Allow QA users to see all ODM firmware uploaded
* Allow setting the category to 'Unknown'
* Allow specifying firmware versions when using the advanced requires editor
* Do not allow component modification when in testing and stable
* Do not backtrace if a component does not have a <name>
* Do not include a CSRF for public search queries
* Do not include the VersionFormat fallbacks if the fw requries a new enough fwupd
* Do not make the database server explode with a query like 'value=+foo'
* Do not save duplicate <requires>vendor-id</> tags to the metadata
* Ensure firmware again when it changes state
* Fix a regression when component claims were not being added
* Fix regression when getting security level of component
* Improve the report query speed by several orders of magnitude
* Include the vendor tag in the rewritten metainfo and AppStream XML
* Invalidate ODM remotes when a firmware is demoted back to private
* List <id> requires first in the metadata
* Make it more obvious that the firmware is waiting to be signed
* Make the LVFS username case insensitive
* Make the markdown to root function more robust
* Parse the <metadata_license> even when not in strict mode
* Set the SHA256 content checksum in the metadata
* Show a disabled button when the user has no ACL to move the firmware

LVFS Releases
#############

1.1.6 (2020-01-28)
==================

This release adds the following features:

* Add a atom feed to public device page
* Add a claim for systems supporting Intel BiosGuard and BootGuard
* Add a ``dell-bios`` version format
* Add a page to list consultants that can work on the LVFS
* Add a plugin to add component claims for specific shard GUIDs
* Add a release tag to store the vendor-specific firmware identifier
* Allow adding component claims based on the hash of a shard
* Allow syncing with other firmware databases
* Move the formal documentation to Sphinx

This release fixes the following bugs:

* Add many more database indexes to improve performance
* Add some missing vendor checks when proxying to the user ACL
* Allow vendor managers to see a read-only view of the restrictions page
* Always use the vendor-id restrictions of the ODM, not the OEM
* Fix support for multiple ``LVFS::VersionFormat`` tags
* Include a vendor ID by default for testing accounts
* Make more queries compatible with PostgreSQL
* Never include firmware in private in any embargo remote
* Only show vendors with LVFS users on the vendorlist
* Reduce the memory consumption when running cron and doing yara queries
* Update the firmware report count at upload time
* Use SHA256 when storing the upload checksum
* Use the correct filename for a PKCS-7 payload signature
* Use UEFIExtract rather than chipsec to extract shards

1.1.5 (2019-11-15)
==================

This release adds the following features:

* Add support for matching firmware requirements on device parents
* Allow researchers to run YARA queries on the public firmware
* Allow the blocklist plugin to add persistent claims
* Use PSPTool to parse the AMD PSP section

This release fixes the following bugs:

* Add the Dell PFS as a component shard
* Allow the owner of the firmware to always change update details
* Convert to Blueprints to improve page loading time
* Do not hardcode the list of version formats in various places
* Do not share the shard name between GUIDs
* Only auto-demote stable-to-testing, not testing-to-embargo or stable-to-embargo
* Show the version format versions with no trailing zeros

1.1.4 (2019-09-26)
==================

This release adds the following features:

* Add component issues such as CVEs in a structured way
* Add more OEM notification emails for ODM actions
* Add support for name variant suffixes
* Add vendor namespaces to enforce ODM relationships
* Allow searching for CVEs when logged in
* Allow the OEM to better control what the ODM is able to do

This release fixes the following bugs:

* Allow vendors to optionally disable the inf parsing
* Blacklist generic GUIDs like 'main-system-firmware'
* Check the source and release URLs are valid if provided
* Do not show deleted firmware on the recent list on the dashboard
* Don't auto-demote firmware because of old reports
* Enforce the VersionFormat if the version is an integer
* Fix a crash if uploading a file with a missing metadata_license tag
* Provide a way to un-disable users as a vendor manager
* Regenerate embargo remotes ever 5 minutes
* Use a sane error message on upload when a component drops a GUID

1.1.3 (2019-08-06)
==================

This release adds the following features:

* Show a nag message for admin or manager account without 2FA
* Do not use AppStream-glib to parse the metainfo file
* Automatically demote firmware with more than 5 failures and a success rate of %lt;70%
* Allow firmware or vendors to enable DoNotTrack functionality
* Show the user capabilities in the headerbar
* Protect all forms against CSRF

This release fixes the following bugs:

* Retry all existing tests if the category or protocol is changed
* Do not allow forward slashes in AppStream ID values
* Use a proper AppStream ID for the CHIPSEC shards
* Show flashed messages on the landing page
* Better support firmware requires without conditions or versions
* Do not allow AppStream markup in non description elements

1.1.2 (2019-05-28)
==================

This release adds the following features:

* Add a new plugin to check portable executable files
* Save the shards in an on-disk cache which allows re-running tests
* Add a failure for any firmware that is signed with a 3-year expired certificate
* Add shard certificates to the database and show them in the component view

This release fixes the following bugs:

* Make it easier to enter multiline text as plugin settings

1.1.1 (2019-05-21)
==================

This release adds the following features:

* Allow managers to edit their own list of embargoed countries
* Record the size and entropy of the component shards when parsing
* Analyze Intel ME firmware when it is uploaded

This release fixes the following bugs:

* Do not expect device checksums for ME or EC firmware

1.1.0 (2019-05-14)
==================

This release adds the following features:

* Run CHIPSEC on all UEFI firmware files
* Show details of UEFI firmware volumes for capsule updates
* Show differences between public revisions of firmware
* Provide some extra information about detected firmware shards

This release fixes the following bugs:

* Only decompress the firmware once when running tests
* Make the component detail page a bit less monolithic
* Never leave tests in the running state if a plugin crashes

1.0.0 (2019-05-02)
==================

This release adds the following features:

* Allow the admin to change the AppStream ID or name of components

This release fixes the following bugs:

* Do not allow the telemetry card title to overflow
* Ensure the ``firmware-flashed`` value is a valid lowercase GUID
* Make the component requirements page easier to use
* Do not add duplicate ``<hardware>`` values
* Remove the hard-to-use breadcrumb and use a single back button
