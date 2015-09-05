(function() {
  var isRoot, notifier, packageJSON, updateNotifier;

  updateNotifier = require('update-notifier');

  isRoot = require('is-root');

  packageJSON = require('../../package.json');

  if (!isRoot()) {
    notifier = updateNotifier({
      pkg: packageJSON
    });
  }

  exports.hasAvailableUpdate = function() {
    return notifier != null;
  };

  exports.notify = function() {
    if (!exports.hasAvailableUpdate()) {
      return;
    }
    return notifier.notify();
  };

}).call(this);