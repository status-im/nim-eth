--threads:on
--path:"$projectDir/../.."
--d:testing
when defined(windows):
  switch("d", "chronicles_colors=NoColors")

