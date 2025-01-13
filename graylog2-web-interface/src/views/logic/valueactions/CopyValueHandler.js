import type { ValueActionHandler } from './ValueActionHandler';

const CopyValueHandler: ValueActionHandler = ({value}) => {
  if (value === undefined) {
    return Promise.reject(new Error('Unable to add highlighting for missing value.'));
  }

  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(value).then(
      () => {
        return Promise.resolve();
        /* clipboard successfully set */
      },
      () => {
        return Promise.reject(new Error('Impossible to copy value in Clipboard'))
        /* clipboard write failed */
      },
    );
  } else {
    //Used only for http
    // Use the 'out of viewport hidden text area' trick
    const textArea = document.createElement("textarea");
    textArea.value = value;

    // Move textarea out of the viewport so it's not visible
    textArea.style.position = "absolute";
    textArea.style.left = "-999999px";

    document.body.prepend(textArea);
    textArea.select();

    try {
      document.execCommand('copy');
    } catch (error) {
      console.error(error);
    } finally {
      textArea.remove();
    }
    return Promise.resolve();
  }
}

CopyValueHandler.isEnabled = () => {return true};

export default CopyValueHandler;
