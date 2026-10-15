# Checkout smoke test

Run the checkout smoke test on the site the person names.

1. Open the start page with `browser_navigate` and read it with
   `browser_snapshot`.
2. Add the first product to the basket with `browser_click`, then fill the
   delivery form with `browser_fill_form` using clearly synthetic values.
3. Confirm the basket total with `browser_verify_text_visible` and keep a
   screenshot of each step with `browser_take_screenshot`.
4. Do not submit the order, and do not use `browser_evaluate`.

Write what you saw, step by step, with `write_report`.
